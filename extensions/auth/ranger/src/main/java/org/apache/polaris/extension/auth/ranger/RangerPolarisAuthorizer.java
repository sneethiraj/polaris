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

import com.google.common.base.Preconditions;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.iceberg.exceptions.ForbiddenException;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.auth.PolarisAuthorizer;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.config.FeatureConfiguration;
import org.apache.polaris.core.config.RealmConfig;
import org.apache.polaris.core.entity.PolarisBaseEntity;
import org.apache.polaris.core.entity.PolarisEntityConstants;
import org.apache.polaris.core.entity.PolarisEntityCore;
import org.apache.polaris.core.persistence.PolarisResolvedPathWrapper;
import org.apache.polaris.extension.auth.ranger.utils.RangerUtils;
import org.apache.ranger.authz.api.RangerAuthorizer;
import org.apache.ranger.authz.api.RangerAuthzException;
import org.apache.ranger.authz.embedded.RangerEmbeddedAuthorizer;
import org.apache.ranger.authz.model.RangerAuthzRequest;
import org.apache.ranger.authz.model.RangerAuthzResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static org.apache.polaris.core.entity.PolarisEntityConstants.getRootPrincipalName;

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

    public static final String SERVICE_TYPE          = "polaris";
    public static final String SERVICE_NAME_PROPERTY = "ranger.plugin.polaris.service.name";

    private static final String OPERATION_NOT_ALLOWED_FOR_USER_ERROR = "Principal '%s' is not authorized for op %s due to PRINCIPAL_CREDENTIAL_ROTATION_REQUIRED_STATE";
    private static final String ROOT_PRINCIPLE_NEEDED_ERROR          = "Principal '%s' is not authorized for op %s as Only root principal can perform this operation";
    private static final String RANGER_AUTH_FAILED_ERROR             = "Principal '%s' with activated PrincipalRoles '%s' and activated grants via '%s' is not authorized for op '%s'";

    private final RealmConfig      realmConfig;
    private final RangerAuthorizer authorizer;
    private final String           serviceName;

    public RangerPolarisAuthorizer(RangerPolarisAuthorizerConfig config, RealmConfig realmConfig) {
        LOG.info("Initializing RangerPolarisAuthorizer");

        Properties rangerProp = RangerUtils.loadProperties(config.configFileName());

        this.realmConfig = realmConfig;
        this.authorizer  = new RangerEmbeddedAuthorizer(rangerProp);
        this.serviceName = rangerProp.getProperty(SERVICE_NAME_PROPERTY);

        try {
            authorizer.init();
        } catch (RangerAuthzException t) {
            LOG.error("Failed to initialize RangerPolarisAuthorizer", t);

            throw new RuntimeException(t);
        }

        LOG.info("RangerPolarisAuthorizer initialized successfully");
    }

    @Override
    public void authorizeOrThrow(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull Set<PolarisBaseEntity> activatedEntities,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nullable PolarisResolvedPathWrapper target,
            @Nullable PolarisResolvedPathWrapper secondary) {
        authorizeOrThrow(polarisPrincipal, activatedEntities, authzOp, target == null ? null : List.of(target), secondary == null ? null : List.of(secondary));
    }

    @Override
    public void authorizeOrThrow(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull Set<PolarisBaseEntity> activatedEntities,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nullable List<PolarisResolvedPathWrapper> targets,
            @Nullable List<PolarisResolvedPathWrapper> secondaries) {
        try {
            if (authzOp == PolarisAuthorizableOperation.ROTATE_CREDENTIALS) {
                boolean enforceCredentialRotationRequiredState = realmConfig.getConfig(FeatureConfiguration.ENFORCE_PRINCIPAL_CREDENTIAL_ROTATION_REQUIRED_CHECKING);

                if (enforceCredentialRotationRequiredState && !polarisPrincipal.getProperties().containsKey(PolarisEntityConstants.PRINCIPAL_CREDENTIAL_ROTATION_REQUIRED_STATE)) {
                    // TODO: enable ranger audit from here to ensure that the request denied captured.
                    throw new ForbiddenException(OPERATION_NOT_ALLOWED_FOR_USER_ERROR, polarisPrincipal.getName(), authzOp.name());
                }
            } else if (authzOp == PolarisAuthorizableOperation.RESET_CREDENTIALS) {
                boolean isRootPrincipal = getRootPrincipalName().equals(polarisPrincipal.getName());

                if (!isRootPrincipal) {
                    // TODO: enable ranger audit from here to ensure that the request denied captured.
                    throw new ForbiddenException(ROOT_PRINCIPLE_NEEDED_ERROR, polarisPrincipal.getName(), authzOp.name());
                }
            } else if (!isAccessAuthorized(polarisPrincipal, activatedEntities, authzOp, targets, secondaries)) {
                throw new ForbiddenException(RANGER_AUTH_FAILED_ERROR,
                        polarisPrincipal.getName(),
                        polarisPrincipal.getRoles(),
                        activatedEntities.stream().map(PolarisEntityCore::getName).collect(Collectors.toSet()),
                        authzOp.name());
            }
        } catch(IllegalStateException ise) {
            LOG.error("Failed to authorize principal {} for op {}. Throwing exception. {}", polarisPrincipal, authzOp, ise);

            throw ise;
        }
    }

    private boolean isAccessAuthorized(
            @Nonnull PolarisPrincipal polarisPrincipal,
            @Nonnull Set<PolarisBaseEntity> activatedEntities,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nullable List<PolarisResolvedPathWrapper> targets,
            @Nullable List<PolarisResolvedPathWrapper> secondaries) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("isAuthorized: users={}, groups={}", polarisPrincipal.getName(), String.join(",", polarisPrincipal.getRoles()));

            LOG.debug("isAuthorized: activatedEntities={}",
                    activatedEntities.stream()
                            .map(e -> RangerUtils.toResourceType(e.getType()) + ":" + e.getName())
                            .collect(Collectors.joining(",")));

            LOG.debug("isAuthorized: authzOp={}", authzOp.name());

            LOG.debug("isAuthorized: permissions={}",
                    authzOp.getPrivilegesOnTarget().stream()
                            .map(RangerUtils::toAccessType)
                            .collect(Collectors.joining(",")));

            if (targets != null) {
                LOG.debug("isAuthorized: targets={}",
                        targets.stream()
                                .map(RangerUtils::toResourcePath)
                                .collect(Collectors.joining(",")));
            }

            if (secondaries != null) {
                LOG.debug("isAuthorized: secondaries={}",
                        secondaries.stream()
                                .map(RangerUtils::toResourcePath)
                                .collect(Collectors.joining(",")));
            }
        }

        return isAccessAuthorized(polarisPrincipal, authzOp, targets, secondaries);
    }

    private boolean isAccessAuthorized(
            @Nonnull PolarisPrincipal principal,
            @Nonnull PolarisAuthorizableOperation authzOp,
            @Nullable List<PolarisResolvedPathWrapper> targets,
            @Nullable List<PolarisResolvedPathWrapper> secondaries) {
        boolean accessGranted = true;

        if (targets != null && !targets.isEmpty()) {
            for (PolarisResolvedPathWrapper target : targets) {
                if (!isTargetAuthorized(principal, authzOp, target)) {
                    accessGranted = false;

                    LOG.debug("Failed to satisfy privilege {} for principal {} on entity {}", authzOp.name(), principal.getName(), target);
                }
            }
        } else {
            Preconditions.checkState(authzOp.getPrivilegesOnTarget().isEmpty(), "No target provided to authorize %s for privilege %s", authzOp, authzOp.getPrivilegesOnTarget());
        }

        if (secondaries != null && !secondaries.isEmpty()) {
            for (PolarisResolvedPathWrapper secondary : secondaries) {
                if (!isSecondaryAuthorized(principal, authzOp, secondary)) {
                    accessGranted = false;

                    LOG.debug("Failed to satisfy privilege {} for principal {} on entity {}", authzOp.name(), principal.getName(), secondary);
                }
            }
        } else {
            Preconditions.checkState(authzOp.getPrivilegesOnSecondary().isEmpty(), "No secondary provided to authorize %s for privilege %s", authzOp, authzOp.getPrivilegesOnSecondary());
        }

        return accessGranted ;
    }

    private boolean isTargetAuthorized(@Nonnull PolarisPrincipal principal, @Nonnull PolarisAuthorizableOperation authzOp, PolarisResolvedPathWrapper entity) {
        boolean accessAllowed = false;

        try {
            RangerAuthzRequest request = RangerUtils.toAccessRequest(principal,entity, authzOp, RangerUtils.toPermissions(authzOp.getPrivilegesOnTarget()), SERVICE_TYPE, serviceName);
            RangerAuthzResult  result  = authorizer.authorize(request);

            accessAllowed = RangerAuthzResult.AccessDecision.ALLOW.equals(result.getDecision()) ;
        } catch (RangerAuthzException e) {
            LOG.error("Ranger authorization failed for principal {} on entity {}", principal, entity, e);
        }

        LOG.debug("RangerPolicyEval: result = {}", accessAllowed);

        return accessAllowed ;
    }

    private boolean isSecondaryAuthorized(@Nonnull PolarisPrincipal principal, @Nonnull PolarisAuthorizableOperation authzOp, PolarisResolvedPathWrapper entity) {
        boolean accessAllowed = false;

        try {
            RangerAuthzRequest request = RangerUtils.toAccessRequest(principal,entity, authzOp, RangerUtils.toPermissions(authzOp.getPrivilegesOnSecondary()), SERVICE_TYPE, serviceName);
            RangerAuthzResult  result  = authorizer.authorize(request);

            accessAllowed = RangerAuthzResult.AccessDecision.ALLOW.equals(result.getDecision()) ;
        } catch (RangerAuthzException e) {
            LOG.error("Ranger authorization failed for principal {} on entity {}", principal, entity, e);
        }

        LOG.debug("RangerPolicyEval: result = {}", accessAllowed);

        return accessAllowed ;
    }
}
