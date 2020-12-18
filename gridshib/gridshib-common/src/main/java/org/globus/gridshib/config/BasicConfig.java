/*
 * Copyright 2006-2009 University of Illinois
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.globus.gridshib.config;

import java.io.File;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.globus.gsi.X509Credential;

/**
 * Basic configuration properties for the GridShib SAML Tools.
 *
 * @since 0.4.0
 */
public class BasicConfig {

    private static Log logger =
        LogFactory.getLog(BasicConfig.class.getName());

    // config properties read from config file:
    // TODO: why are these static?
    private static String entityID;
    private static String format;
    private static String template;
    private static String nameQualifier;
    private static String dateTimePattern;
    private static X509Credential credential;

    public BasicConfig() {
        this.entityID = null;
        this.format = null;
        this.template = null;
        this.nameQualifier = null;
        this.dateTimePattern = null;
        this.credential = null;
    }

    public String getEntityID() {
        return this.entityID;
    }

    public void setEntityID(String entityID) {
        this.entityID = entityID;
    }

    public String getFormat() {
        return this.format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getTemplate() {
        return this.template;
    }

    public void setTemplate(String template) {
        this.template = template;
    }

    public String getFormattedName(String name) {
        if (this.template == null) {
            return null;
        }
        return this.template.replaceAll("%PRINCIPAL%", name);
    }

    public String getNameQualifier() {
        return this.nameQualifier;
    }

    public void setNameQualifier(String nameQualifier) {
        this.nameQualifier = nameQualifier;
    }

    public String getDateTimePattern() {
        return this.dateTimePattern;
    }

    public void setDateTimePattern(String dateTimePattern) {
        this.dateTimePattern = dateTimePattern;
    }

    public X509Credential getCredential() {
        return this.credential;
    }

    public void setCredential(X509Credential credential) {
        this.credential = credential;
    }
}
