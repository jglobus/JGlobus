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
package org.globus.gsi.util;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public final class FileUtil {

    private FileUtil() {
        //This should not be instantiated.
    }

    public static File createFile(String filename) throws IOException {

        File f = new File(filename);
        if (!f.createNewFile()) {
            FileUtils.forceDelete(f);
            if (!f.createNewFile()) {
                throw new SecurityException(
                        "Failed to atomically create new file");
            }
        }
        return f;
    }

}
