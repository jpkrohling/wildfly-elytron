/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.util;

/**
 * A realm mapper.  Examines the user name and translates it into a realm name.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface RealmMapper {

    /**
     * Get the realm mapping.  Return {@code null} if the default realm should be used.
     *
     * @param userName the user name
     * @return the realm, or {@code null} to use the default realm
     */
    String getRealmMapping(String userName);

    /**
     * A realm mapper which always maps to the default realm.
     */
    RealmMapper DEFAULT_REALM_MAPPER = new RealmMapper() {
        public String getRealmMapping(final String userName) {
            return null;
        }
    };
}
