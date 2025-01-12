#!/bin/bash

domains=(
  "akamaicontainer.com"
  "akamaitechcloudservices.com"
  "azuredeploystore.com"
  "azureonlinecloud.com"
  "azureonlinestorage.com"
  "dunamistrd.com"
  "glcloudservice.com"
  "journalide.org"
  "msedgepackageinfo.com"
  "msedgeupdate.net"
  "msstorageazure.com"
  "msstorageboxes.com"
  "officeaddons.com"
  "officestoragebox.com"
  "pbxcloudeservices.com"
  "pbxphonenetwork.com"
  "pbxsources.com"
  "qwepoi123098.com"
  "sbmsa.wiki"
  "sourceslabs.com"
  "visualstudiofactory.com"
  "zacharryblogs.com"
)

for domain in "${domains[@]}"
do
  dig $domain
done
