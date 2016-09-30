#!/usr/bin/env bash

#curl -X PUT -H "Content-type: application/json" localhost:4985/contacts/_design/contacts --data @views/allViews

#create supercouch user
curl -L -X POST -H 'Content-Type: application/json' -d '{"name":"appyadmin","password":"appyadmin","admin_channels":["*"]}' http://localhost:4985/appydb/_user/
