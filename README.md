# Kismet MAC Track #

This program will help you locate a WIFI device during for example a CTF.  
It takes a Kismet SQLite database and a MAC-address of the device to be located as input values.  

It also assumes you have a working GPS.
The locations and signal strength are fed to your Elasticsearch server.  
Don't forget to add the elastic schema before ingesting your data.  

```
PUT _template/kismet-mac-location
{
  "index_patterns": ["kismet-mac-location*"],
  "settings": {
    "number_of_shards": 1
  },
  "mappings": {
      "_source": {
        "enabled": true
      },
      "properties": {
      "geo.location": {
          "type": "geo_point"
        },
       "@timestamp": {
            "type": "date"
       },
      }
    }
  }
}
``` 
