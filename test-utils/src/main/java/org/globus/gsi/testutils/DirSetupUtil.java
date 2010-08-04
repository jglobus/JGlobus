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
package org.globus.gsi.testutils;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class DirSetupUtil {

    private Map<String, FileSetupUtil> map = new HashMap<String, FileSetupUtil>();
    private String[] fileNames;
    private File tempDir;

    public DirSetupUtil(String[] inputFileNames) {

        this.fileNames = inputFileNames;
    }

    public void createTempDirectory() throws IOException {

        this.tempDir =
                File.createTempFile("temp", Long.toString(System.nanoTime()));

        if (!(tempDir.delete())) {
            throw new IOException(
                    "Could not delete temp file: " +
                            this.tempDir.getAbsolutePath());
        }

        if (!(tempDir.mkdir())) {
            throw new IOException(
                    "Could not create temp directory: " +
                            this.tempDir.getAbsolutePath());
        }

    }

    public void copy() throws Exception {

        for (String fileName : this.fileNames) {
            FileSetupUtil util = new FileSetupUtil(fileName);
            util.copyFileToTemp(this.tempDir);
            this.map.put(fileName, util);
        }
    }

    // Original file name.

    public FileSetupUtil getFileSetupUtil(String filename) {

        return this.map.get(filename);
    }

    public File getTempDirectory() {

        return this.tempDir;
    }

    public String getTempDirectoryName() {
        if (this.tempDir != null) {
            return this.tempDir.getAbsolutePath();
        }
        return null;
    }

    public void delete() throws IOException {

        FileUtils.deleteDirectory(this.tempDir);
    }
}
