#!/usr/bin/env python3

"""
This program takes a kismetdb file and a mac address as input values.
Looks for all packets in the kismetdb file and extracts their location.

It then maps the location to Elasticsearch.

"""

import argparse
import datetime
import logging
import sqlite3
import sys
from hashlib import md5

import elasticsearch
from elasticsearch import helpers

Log_Format = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig(stream=sys.stdout,
                    format=Log_Format,
                    level=logging.INFO)
logger = logging.getLogger()


def parse_arguments():
    """ Parses input arguments, file and MAC is required."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="Kismet database file", required=True)
    parser.add_argument("-m", "--mac", help="MAC address, colon separated.", required=True)
    parser.add_argument("-e", "--elasticsearch",
                        help="IP to elastic server, if password required, then: http://user:pass@ip",
                        required=False)
    parser.add_argument("-i", "--index", help="Name of the elasticsearch index, defaults to kismet-mac-location",
                        required=False)
    args = parser.parse_args()
    kismet_file = args.file
    mac_address = args.mac
    if args.elasticsearch:
        elastic_server = elasticsearch.Elasticsearch(hosts=args.elasticsearch)
    else:
        elastic_server = elasticsearch.Elasticsearch(hosts="127.0.0.1")
        # elastic_server = elasticsearch.Elasticsearch(hosts="http://elastic:qwerty@127.0.0.1") # For password
    if args.index:
        elastic_index = args.index
    else:
        elastic_index = "kismet-mac-location"
    return kismet_file, mac_address, elastic_server, elastic_index



def sqlite3_generator(sqlite3_file, sql_query):
    """ Create a generator object that returns items from the kismetdb-file.
    Input is a correct SQL query."""
    db = sqlite3.connect(sqlite3_file)
    cursor = db.cursor()
    cursor.execute(sql_query)
    for i in cursor.fetchall():
        yield i


def read_mac_from_file(kismet_file, mac_address):
    """ Read data from all devices. """
    sql_query = str("SELECT * FROM packets WHERE sourcemac=\"%s\"" % mac_address)
    kismet_generator = sqlite3_generator(kismet_file, sql_query)
    return kismet_generator


def md5_string(*args):
    """Returns the MD5 sum of all input strings, can be one string or a list of strings."""
    _l = []
    for a in args:
        _l.append(a)
    text = ''.join(_l)
    m = md5()
    m.update(text.encode())
    md5_digest = m.hexdigest()
    return md5_digest


def kismet_packet_data_extractor(packet_tuple):
    """ Returns a dictionary based on the information from the kismet database """
    epoch = packet_tuple[0]
    timestamp = datetime.datetime.fromtimestamp(epoch)
    mac = packet_tuple[3]
    dest_mac = packet_tuple[4]
    lat = packet_tuple[8]
    lon = packet_tuple[9]
    signal = packet_tuple[14]
    kismet_dict_for_es = {
        "@timestamp": timestamp,
        "network.mac": mac,
        "network.mac_destination": dest_mac,
        "geo.location": [lon, lat],
        "radio.signal.event": signal
    }
    return kismet_dict_for_es


def list_to_elastic(input_list, elasticsearch_server):
    """ Takes items that has been populated with elastic frame and inserts them to Elastic."""
    helpers.bulk(elasticsearch_server, [x for x in input_list])


def add_elasticsearch_frame_to_dictionary(input_dict, index_name):
    md5_id = md5_string(input_dict["network.mac"], str(input_dict["@timestamp"]))
    if input_dict:
        elastic_input_dict = {
            "_index": index_name,
            "_id": md5_id,
            "_source": input_dict
        }
        return elastic_input_dict
    else:
        logger.error("Elasticsearch dictionary formatter received empty dictionary.")
        return False


def process_kismet_generator(kismet_generator, index_name):
    global COUNTER
    for kismet_object in kismet_generator:
        kismet_dict = kismet_packet_data_extractor(kismet_object)
        es_kismet_dict = add_elasticsearch_frame_to_dictionary(kismet_dict, index_name)
        COUNTER += 1
        yield es_kismet_dict


def main():
    kismet_file, mac_address, elastic_server, elastic_index = parse_arguments()
    print(f"[*] Searching for {mac_address} in {kismet_file}, inserting to Elastic.")
    kismet_generator = read_mac_from_file(kismet_file, mac_address)
    es_kismet_generator = process_kismet_generator(kismet_generator, elastic_index)
    list_to_elastic(es_kismet_generator, elastic_server)
    print(f"[*] Processed {COUNTER} MAC-addresses.")


if __name__ == "__main__":
    main()
