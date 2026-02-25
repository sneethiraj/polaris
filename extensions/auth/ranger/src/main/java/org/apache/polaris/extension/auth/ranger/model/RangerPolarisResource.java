/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.polaris.extension.auth.ranger.model;

import org.apache.polaris.core.entity.PolarisEntity;
import org.apache.polaris.core.persistence.PolarisResolvedPathWrapper;
import org.apache.polaris.core.persistence.ResolvedPolarisEntity;
import org.apache.polaris.extension.auth.ranger.plugin.RangerPolarisPlugin;
import org.apache.polaris.extension.auth.ranger.utils.RangerUtils;
import org.apache.ranger.authz.model.RangerResourceInfo;
import org.apache.ranger.authz.util.RangerResourceNameParser;

public class RangerPolarisResource extends RangerResourceInfo {

    public RangerPolarisResource(PolarisResolvedPathWrapper resourcePath) {
        setName(RangerPolarisResource.getResourcePath(resourcePath));
    }

    public static String getResourcePath(PolarisResolvedPathWrapper resolvedPath) {
        StringBuilder sb = new StringBuilder();
        sb.append(RangerUtils.toResourceType(resolvedPath.getResolvedLeafEntity().getEntity().getType()))
                .append(RangerResourceNameParser.RRN_RESOURCE_TYPE_SEP) ;
        boolean isFirst = true ;
        for (ResolvedPolarisEntity entity : resolvedPath.getResolvedFullPath()) {
            if (!isFirst) {
                sb.append(RangerResourceNameParser.DEFAULT_RRN_RESOURCE_SEP) ;
            }
            else {
                isFirst = false ;
            }
            sb.append(entity.getEntity().getName()) ;
        }
        return sb.toString() ;
    }

}
