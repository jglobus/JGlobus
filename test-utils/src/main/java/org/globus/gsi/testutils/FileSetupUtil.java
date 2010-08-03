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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class FileSetupUtil {

    private String filename;
    private File tempFile;
    private Log logger = LogFactory.getLog(getClass());
    private static final int SLEEP_LENGTH = 1000;

    public FileSetupUtil(String inputFileName) {

        this.filename = inputFileName;
    }

    public File getTempFile() {
        return this.tempFile;
    }

    public void copyFileToTemp() throws IOException {

        copyFileToTemp(null);
    }

    public void copyFileToTemp(File dir) throws IOException {
        ClassLoader loader = FileSetupUtil.class.getClassLoader();
        int index = filename.lastIndexOf('.');
        this.tempFile = File.createTempFile("globusSecurityTest", filename.substring(index, filename.length()), dir);
        InputStream in = loader.getResourceAsStream(this.filename);
        FileWriter writer = new FileWriter(this.tempFile);
        try {
            int c = in.read();
            while (c != -1) {
                writer.write(c);
                c = in.read();
            }
        } finally {
            in.close();
            writer.close();
        }
    }

    public String getAbsoluteFilename() {
        return this.tempFile.getAbsolutePath();
    }

    public String getTempFilename() {
        return this.tempFile.getName();
    }

    public URL getURL() {
        URL url = null;
        try {
            url = this.tempFile.toURI().toURL();
        } catch (MalformedURLException e) {
            logger.info("This should not have happened", e);  //This really shouldn't happen, so let's print in the random chance it does
        }
        return url;
    }

    public void deleteFile() {
        if (this.tempFile != null && !this.tempFile.delete()) {
            logger.info("File was not deleted: " + this.tempFile.getAbsolutePath());
        }
    }

    public void modifyFile() throws InterruptedException, IOException {
        if (this.tempFile != null) {
            // FIXME: only way for modified time to have some delta
            Thread.sleep(SLEEP_LENGTH);
            FileWriter writer = new FileWriter(this.tempFile, true);
            try {
                writer.write("\n");
            } finally {
                writer.close();

            }
        }
    }
}
