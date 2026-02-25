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

import jakarta.annotation.Nonnull;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.persistence.PolarisResolvedPathWrapper;
import org.apache.polaris.core.persistence.ResolvedPolarisEntity;
import org.apache.polaris.extension.auth.ranger.RangerPolarisAuthorizer;
import org.apache.polaris.extension.auth.ranger.plugin.RangerPolarisPlugin;
import org.apache.polaris.extension.auth.ranger.utils.RangerUtils;
import org.apache.ranger.authz.model.RangerAccessContext;
import org.apache.ranger.authz.model.RangerAccessInfo;
import org.apache.ranger.authz.model.RangerAuthzRequest;
import org.apache.ranger.authz.model.RangerResourceInfo;
import org.apache.ranger.authz.model.RangerUserInfo;
import org.apache.ranger.authz.util.RangerResourceNameParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public class RangerPolarisAccessRequest extends RangerAuthzRequest {

    private static final Logger LOG = LoggerFactory.getLogger(RangerPolarisAccessRequest.class);

    public RangerPolarisAccessRequest(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull PolarisResolvedPathWrapper target,
            @Nonnull PolarisAuthorizableOperation authzOp) {

        setUser(new RangerUserInfo(polarisPrincipal.getName(), Collections.emptyMap(),polarisPrincipal.getRoles(),null));

        RangerAccessInfo accessInfo = new RangerAccessInfo();
        setAccess(accessInfo);
        accessInfo.setAction(authzOp.name());
        Set<String> permissionSet = authzOp.getPrivilegesOnTarget().stream()
                .map(RangerUtils::toAccessType).collect(Collectors.toSet());
        accessInfo.setPermissions(permissionSet);

        RangerPolarisResource resource = new RangerPolarisResource(target) ;
        accessInfo.setResource(resource) ;

        LOG.info("user: {}, group: {}, permissions: {}, resource: {} ",
                getUser().getName(),
                String.join(",", getUser().getGroups()),
                String.join(",", permissionSet),
                resource.getName()) ;
    }




}
