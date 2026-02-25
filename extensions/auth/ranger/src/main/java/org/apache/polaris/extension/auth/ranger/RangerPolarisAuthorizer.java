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
package org.apache.polaris.extension.auth.ranger;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.auth.PolarisAuthorizer;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.config.RealmConfig;
import org.apache.polaris.core.entity.PolarisBaseEntity;
import org.apache.polaris.core.persistence.PolarisResolvedPathWrapper;
import org.apache.polaris.extension.auth.ranger.plugin.RangerPolarisPlugin;
import org.apache.ranger.authz.api.RangerAuthzException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

/**
 * Performs hierarchical resolution logic by matching the transively expanded set of grants to a
 * calling principal against the cascading permissions over the parent hierarchy of a target
 * Securable.
 *
 * <p>Additionally, encompasses "specialty" permission resolution logic, such as checking whether
 * the expanded roles of the calling Principal hold SERVICE_MANAGE_ACCESS on the "root" catalog,
 * which translates into a cross-catalog permission.
 */
public class RangerPolarisAuthorizer implements PolarisAuthorizer {
    private static final Logger LOG = LoggerFactory.getLogger(RangerPolarisAuthorizer.class);

    private final RangerPolarisAuthorizerConfig config;
    private final RealmConfig                   realmConfig;
    private final RangerPolarisPlugin           plugin;

    public RangerPolarisAuthorizer(RangerPolarisAuthorizerConfig config, RealmConfig realmConfig) {
        LOG.info("Initializing RangerPolarisAuthorizer");

        this.config      = config;
        this.realmConfig = realmConfig;
        this.plugin      = new RangerPolarisPlugin(config,realmConfig);

        try {
            plugin.init();
        } catch (RangerAuthzException t) {
            LOG.error("Failed to initialize RangerPolarisAuthorizer", t);
            throw new RuntimeException(t);
        }

        LOG.info("RangerPolarisAuthorizer initialized successfully");
    }

    public RangerPolarisAuthorizerConfig getConfig() {
        return config;
    }

    public RealmConfig getRealmConfig() {
        return realmConfig;
    }

    @Override
    public void authorizeOrThrow(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull Set<PolarisBaseEntity> activatedEntities,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nullable PolarisResolvedPathWrapper target,
            @Nullable PolarisResolvedPathWrapper secondary) {
        plugin.authorizeOrThrow(polarisPrincipal, activatedEntities, authzOp, target == null ? null : List.of(target), secondary == null ? null : List.of(secondary));
    }

    @Override
    public void authorizeOrThrow(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull Set<PolarisBaseEntity> activatedEntities,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nullable List<PolarisResolvedPathWrapper> targets,
            @Nullable List<PolarisResolvedPathWrapper> secondaries) {
        plugin.authorizeOrThrow(polarisPrincipal, activatedEntities, authzOp, targets, secondaries);
    }
}
