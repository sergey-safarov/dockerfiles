#!/bin/sh

psql -f /etc/kamailio/db_scripts/kamailio_initdb.sql -U kamailio kamailio
psql -f /etc/kamailio/db_scripts/kamailio-db-rows.sql -U kamailio kamailio
