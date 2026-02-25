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

package org.apache.polaris.extension.auth.ranger.utils;

import jakarta.annotation.Nonnull;
import org.apache.commons.lang3.StringUtils;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.entity.PolarisEntityType;
import org.apache.polaris.core.entity.PolarisPrivilege;
import org.apache.polaris.core.persistence.PolarisResolvedPathWrapper;
import org.apache.polaris.core.persistence.ResolvedPolarisEntity;
import org.apache.polaris.extension.auth.ranger.RangerPolarisAuthorizer;
import org.apache.ranger.authz.model.RangerAccessContext;
import org.apache.ranger.authz.model.RangerAccessInfo;
import org.apache.ranger.authz.model.RangerAuthzRequest;
import org.apache.ranger.authz.model.RangerResourceInfo;
import org.apache.ranger.authz.model.RangerUserInfo;
import org.apache.ranger.authz.util.RangerResourceNameParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

public class RangerUtils {
    private static final Logger LOG = LoggerFactory.getLogger(RangerUtils.class);

    public static Properties loadProperties(String resourcePath) {
        Properties prop = new Properties();

        if (resourcePath != null) {
            resourcePath = resourcePath.trim();

            if (!resourcePath.startsWith("/")) {
                LOG.info("Adding / to the configFileName [{}]", resourcePath);

                resourcePath = "/" + resourcePath;
            }

            try (InputStream in = RangerPolarisAuthorizer.class.getResourceAsStream(resourcePath)) {
                prop.load(in);
            } catch(IOException e){
                LOG.warn("Unable to load config file: [{}]", resourcePath, e);
            }
        }

        return prop ;
    }

    public static String toResourceType(PolarisEntityType entityType) {
        return switch (entityType) {
            case CATALOG -> "catalog";
            case ROOT -> "root" ;
            case TABLE_LIKE ->  "table" ;
            case NAMESPACE -> "namespace" ;
            case PRINCIPAL -> "principal" ;
            case PRINCIPAL_ROLE -> "principal-role" ;
            case CATALOG_ROLE -> "catalog-role" ;
            case POLICY -> "policy" ;
            default -> "none" ;
        } ;
    }

    public static String toAccessType(PolarisPrivilege privilege) {
        return switch (privilege) {
            case SERVICE_MANAGE_ACCESS -> "service-access-manage";
            case CATALOG_MANAGE_ACCESS -> "catalog-access-manage";
            case CATALOG_ROLE_USAGE -> "catalog-role-usage";
            case PRINCIPAL_ROLE_USAGE -> "principal-role-usage";
            case NAMESPACE_CREATE -> "namespace-create";
            case TABLE_CREATE -> "table-create";
            case VIEW_CREATE -> "view-create";
            case NAMESPACE_DROP -> "namespace-drop";
            case TABLE_DROP -> "table-drop";
            case VIEW_DROP -> "view-drop";
            case NAMESPACE_LIST -> "namespace-list";
            case TABLE_LIST -> "table-list";
            case VIEW_LIST -> "view-list";
            case NAMESPACE_READ_PROPERTIES -> "namespace-properties-read";
            case TABLE_READ_PROPERTIES -> "table-properties-read";
            case VIEW_READ_PROPERTIES -> "view-properties-read";
            case NAMESPACE_WRITE_PROPERTIES -> "namespace-properties-write";
            case TABLE_WRITE_PROPERTIES -> "table-properties-write";
            case VIEW_WRITE_PROPERTIES -> "view-properties-write";
            case TABLE_READ_DATA -> "table-data-read";
            case TABLE_WRITE_DATA -> "table-data-write";
            case NAMESPACE_FULL_METADATA -> "namespace-metadata-full";
            case TABLE_FULL_METADATA -> "table-metadata-full";
            case VIEW_FULL_METADATA -> "view-metadata-full";
            case CATALOG_CREATE -> "catalog-create";
            case CATALOG_DROP -> "catalog-drop";
            case CATALOG_LIST -> "catalog-list";
            case CATALOG_READ_PROPERTIES -> "catalog-properties-read";
            case CATALOG_WRITE_PROPERTIES -> "catalog-properties-write";
            case CATALOG_FULL_METADATA -> "catalog-metadata-full";
            case CATALOG_MANAGE_METADATA -> "catalog-metadata-manage";
            case CATALOG_MANAGE_CONTENT -> "catalog-content-manage";
            case PRINCIPAL_LIST_GRANTS -> "principal-grants-list";
            case PRINCIPAL_ROLE_LIST_GRANTS -> "principal-role-grants-list";
            case CATALOG_ROLE_LIST_GRANTS -> "catalog-role-grants-list";
            case CATALOG_LIST_GRANTS -> "catalog-grants-list";
            case NAMESPACE_LIST_GRANTS -> "namespace-grants-list";
            case TABLE_LIST_GRANTS -> "table-grants-list";
            case VIEW_LIST_GRANTS -> "view-grants-list";
            case CATALOG_MANAGE_GRANTS_ON_SECURABLE -> "catalog-grants-manage";
            case NAMESPACE_MANAGE_GRANTS_ON_SECURABLE -> "namespace-grants-manage";
            case TABLE_MANAGE_GRANTS_ON_SECURABLE -> "table-grants-manage";
            case VIEW_MANAGE_GRANTS_ON_SECURABLE -> "view-grants-manage";
            case PRINCIPAL_CREATE -> "principal-create";
            case PRINCIPAL_DROP -> "principal-drop";
            case PRINCIPAL_LIST -> "principal-list";
            case PRINCIPAL_READ_PROPERTIES -> "principal-properties-read";
            case PRINCIPAL_WRITE_PROPERTIES -> "principal-properties-write";
            case PRINCIPAL_FULL_METADATA -> "principal-metadata-full";
            case PRINCIPAL_MANAGE_GRANTS_ON_SECURABLE -> "principal-grants-manage";
            case PRINCIPAL_MANAGE_GRANTS_FOR_GRANTEE -> "principal-grants-for-grantee-manage";
            case PRINCIPAL_ROTATE_CREDENTIALS -> "principal-credentials-rotate";
            case PRINCIPAL_RESET_CREDENTIALS -> "principal-credentials-reset";
            case PRINCIPAL_ROLE_CREATE -> "principal-role-create";
            case PRINCIPAL_ROLE_DROP -> "principal-role-drop";
            case PRINCIPAL_ROLE_LIST -> "principal-role-list";
            case PRINCIPAL_ROLE_READ_PROPERTIES -> "principal-role-properties-read";
            case PRINCIPAL_ROLE_WRITE_PROPERTIES -> "principal-role-properties-write";
            case PRINCIPAL_ROLE_FULL_METADATA -> "principal-role-metadata-full";
            case PRINCIPAL_ROLE_MANAGE_GRANTS_ON_SECURABLE -> "principal-role-grants-manage";
            case PRINCIPAL_ROLE_MANAGE_GRANTS_FOR_GRANTEE -> "principal-role-grants-for-grantee-manage";
            case CATALOG_ROLE_CREATE -> "catalog-role-create";
            case CATALOG_ROLE_DROP -> "catalog-role-drop";
            case CATALOG_ROLE_LIST -> "catalog-role-list";
            case CATALOG_ROLE_READ_PROPERTIES -> "catalog-role-properties-read";
            case CATALOG_ROLE_WRITE_PROPERTIES -> "catalog-role-properties-write";
            case CATALOG_ROLE_FULL_METADATA -> "catalog-role-metadata-full";
            case CATALOG_ROLE_MANAGE_GRANTS_ON_SECURABLE -> "catalog-role-grants-manage";
            case CATALOG_ROLE_MANAGE_GRANTS_FOR_GRANTEE -> "catalog-role-grants-for-grantee-manage";
            case POLICY_CREATE -> "policy-create";
            case POLICY_READ -> "policy-read";
            case POLICY_DROP -> "policy-drop";
            case POLICY_WRITE -> "policy-write";
            case POLICY_LIST -> "policy-list";
            case POLICY_FULL_METADATA -> "policy-metadata-full";
            case POLICY_ATTACH -> "policy-attach";
            case POLICY_DETACH -> "policy-detach";
            case CATALOG_ATTACH_POLICY -> "catalog-policy-attach";
            case NAMESPACE_ATTACH_POLICY -> "namespace-policy-attach";
            case TABLE_ATTACH_POLICY -> "table-policy-attach";
            case CATALOG_DETACH_POLICY -> "catalog-policy-detach";
            case NAMESPACE_DETACH_POLICY -> "namespace-policy-detach";
            case TABLE_DETACH_POLICY -> "table-policy-detach";
            case POLICY_MANAGE_GRANTS_ON_SECURABLE -> "policy-grants-manage";
            case TABLE_ASSIGN_UUID -> "table-uuid-assign";
            case TABLE_UPGRADE_FORMAT_VERSION -> "table-format-version-upgrade";
            case TABLE_ADD_SCHEMA -> "table-schema-add";
            case TABLE_SET_CURRENT_SCHEMA -> "table-schema-set-current";
            case TABLE_ADD_PARTITION_SPEC -> "table-partition-spec-add";
            case TABLE_ADD_SORT_ORDER -> "table-sort-order-add";
            case TABLE_SET_DEFAULT_SORT_ORDER -> "table-sort-order-set-default";
            case TABLE_ADD_SNAPSHOT -> "table-snapshot-add";
            case TABLE_SET_SNAPSHOT_REF -> "table-snapshot-ref-set";
            case TABLE_REMOVE_SNAPSHOTS -> "table-snapshots-remove";
            case TABLE_REMOVE_SNAPSHOT_REF -> "table-snapshot-ref-remove";
            case TABLE_SET_LOCATION -> "table-location-set";
            case TABLE_SET_PROPERTIES -> "table-properties-set";
            case TABLE_REMOVE_PROPERTIES -> "table-properties-remove";
            case TABLE_SET_STATISTICS -> "table-statistics-set";
            case TABLE_REMOVE_STATISTICS -> "table-statistics-remove";
            case TABLE_REMOVE_PARTITION_SPECS -> "table-partition-specs-remove";
            case TABLE_MANAGE_STRUCTURE -> "table-structure-manage";
        };
    }

    public static String toResourcePath(PolarisResolvedPathWrapper resolvedPath) {
        StringBuilder sb           = new StringBuilder();
        String        resourceType = RangerUtils.toResourceType(resolvedPath.getResolvedLeafEntity().getEntity().getType());

        sb.append(resourceType).append(RangerResourceNameParser.RRN_RESOURCE_TYPE_SEP) ;

        boolean isFirst = true;

        for (ResolvedPolarisEntity entity : resolvedPath.getResolvedFullPath()) {
            if (!isFirst) {
                sb.append(RangerResourceNameParser.DEFAULT_RRN_RESOURCE_SEP) ;
            } else {
                isFirst = false ;
            }

            sb.append(entity.getEntity().getName()) ;
        }

        return sb.toString() ;
    }

    public static RangerResourceInfo toResourceInfo(PolarisResolvedPathWrapper resourcePath) {
        RangerResourceInfo ret = new RangerResourceInfo();

        ret.setName(toResourcePath(resourcePath));

        return ret;
    }

    public static Set<String> toPermissions(EnumSet<PolarisPrivilege> privileges) {
        return privileges.stream().map(RangerUtils::toAccessType).collect(Collectors.toSet());
    }

    public static RangerAuthzRequest toAccessRequest(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull PolarisResolvedPathWrapper entity,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nonnull Set<String> permissions,
            @Nonnull String serviceType,
            @Nonnull String serviceName) {
        RangerUserInfo      user     = new RangerUserInfo(polarisPrincipal.getName(), Collections.emptyMap(), polarisPrincipal.getRoles(), null);
        RangerAccessInfo    access   = new RangerAccessInfo(RangerUtils.toResourceInfo(entity), authzOp.name(), permissions);
        RangerAccessContext context = new RangerAccessContext(serviceType, serviceName);

        if (LOG.isDebugEnabled()) {
            LOG.debug("user: {}, group: {}, permissions: {}, resource: {} ",
                    user.getName(), StringUtils.join(user.getGroups(), ","), StringUtils.join(permissions, ","), access.getResource().getName());
        }

        return new RangerAuthzRequest(user, access, context);
    }
}
