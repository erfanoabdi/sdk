/**
 * Copyright (C) 2022 Hallo Welt Systeme UG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package lineageos.firewall;

/**
 * Schema constants for the firewall block-events SQLite database.
 *
 * Dashboard clients import this class to avoid hardcoding column names.
 * When DB_VERSION is bumped, update CREATE_TABLE and add an onUpgrade migration
 * in FirewallBlockDatabase.
 */
public final class BlockEventSchema {

    public static final int DB_VERSION = 1;

    public static final String TABLE = "block_events";

    public static final String COL_ID            = "id";
    public static final String COL_TIMESTAMP     = "timestamp";
    public static final String COL_DOMAIN        = "domain";
    public static final String COL_APP_NAME      = "app_name";
    public static final String COL_APP_PKG       = "app_pkg";
    /** 1 = HTTPS (port 443), 0 = HTTP (port 80) */
    public static final String COL_IS_HTTPS      = "is_https";
    /** 1 = blacklist mode, 0 = whitelist mode */
    public static final String COL_IS_BLACKLIST  = "is_blacklist";
    /** "manual" or "template" */
    public static final String COL_SOURCE_TYPE   = "source_type";
    /** Template title; null when source_type = "manual" */
    public static final String COL_TEMPLATE_NAME = "template_name";
    /** null / "temp" / "perm" */
    public static final String COL_ALLOWED_TYPE  = "allowed_type";
    /** Epoch-ms when allowed; 0 if never allowed */
    public static final String COL_ALLOWED_AT    = "allowed_at";

    private BlockEventSchema() {}
}
