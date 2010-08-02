/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.globus.gsi.filestore;

import java.io.File;
import java.io.FilenameFilter;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 11:28:38 AM
 * To change this template use File | Settings | File Templates.
 */
public class SigningPolicyFilter implements FilenameFilter {

    public static final String SIGNING_POLICY_FILE_SUFFIX = ".signing_policy";

    public boolean accept(File dir, String file) {
        if (file == null) {
            throw new IllegalArgumentException();
        }
        return file.endsWith(SIGNING_POLICY_FILE_SUFFIX);
    }
}