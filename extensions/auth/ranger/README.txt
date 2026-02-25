#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

Before Starting 
=================

1. The Polaris Authorization is integated into Apache Ranger on 2.8.0 release and
   you must be running Apache Ranger 2.8.0+ version. 

Setup Instruction
=================

1. Add/Modify the following config properties in application.properties file 
   (eg: runtime/defaults/src/main/resources/application.properties)
#---------------------------------------------
polaris.authorization.type=ranger
polaris.authorization.ranger.config-file-name=ranger-plugin.properties
#---------------------------------------------

2. Copy the sample ranger-pluin.properties file from sample-conf folder to
   the folder where application.properties file is located and
   modify the config properties according your ranger installation.

3. Restart the polaris service to see that all authorization(s) are enforced
   by Ranger Policies with audit records available in centralized ranger console

