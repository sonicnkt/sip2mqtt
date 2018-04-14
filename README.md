# sip2mqtt
A SIP monitoring script that publishes incoming calls with CallerID to an MQTT channel.

This is a modification of Martin Tremblay's great script with added support to look up numbers in a vcard file.

I have only tested this with a vcf exported from Nextcloud (V.13).

Im using his docker container to run the script on my server ([pjsip-docker](https://github.com/MartyTremblay/pjsip-docker)).


## usage

Allows the monitoring of SIP connections and publishes the CallerID payload to an MQTT channel. The script requires the following parametters:

```bash
-a MQTT_ADDRESS, --mqtt_address MQTT_ADDRESS
                    the MQTT broker address string
-t MQTT_PORT,    --mqtt_port MQTT_PORT
                    the MQTT broker port number
-u MQTT_USERNAME, --mqtt_username MQTT_USERNAME
                    the MQTT broker username
-p MQTT_PASSWORD, --mqtt_password MQTT_PASSWORD
                    the MQTT broker password
-d SIP_DOMAIN,    --sip_domain SIP_DOMAIN
                    the SIP domain
-n SIP_USERNAME,  --sip_username SIP_USERNAME
                    the SIP username
-s SIP_PASSWORD,  --sip_password SIP_PASSWORD
                    the SIP password
```                    
Example:
```bash
python /opt/sip2mqtt/sip2mqtt.py -t16491 -afoo.cloudmqtt.com -uSip2Mqtt -pSECRET -dfoo.voip.ms -nSUB_DID -sSECRET -vvv
```                   
More optional parametters can be viewed by running python sip2mqtt.py -h

## docker usage
As the docker image is missing this script as well as a vcard for contacts and a necessary python module im using a startup script with the container.

sip2mqtt_startup.sh
```bash
#!/bin/bash
pip install vobject

export MQTT_DOMAIN='127.0.0.1'
export MQTT_PORT='1883'
export MQTT_USERNAME='mqttuser'
export MQTT_PASSWORD='mqttpass'
export SIP_DOMAIN='provider.org'
export SIP_SERVER='123.sip.provider.org'
export SIP_USERNAME='mysipuser'
export SIP_PASSWORD='mysecretsippassword'
export VCARD='input.vcf'

python /opt/sip2mqtt/sip2mqtt.py
```
Put the script together with my modified sip2mqtt.py and a input.vcf file in a folder you make accessible from the container.
The docker run command im using looks like this:
```bash
docker run --net=host -v /hostsystem/sip2mqtt:/opt/sip2mqtt retrohunter/pjsip-docker:2.x sh /opt/sip2mqtt/sip2mqtt_startup.sh.sh
```
