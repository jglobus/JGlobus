package org.globus.gsi.filestore;

import java.io.File;
import java.io.FilenameFilter;

/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 30, 2009
 * Time: 10:46:27 AM
 * To change this template use File | Settings | File Templates.
 */
public class TrustAnchorFilter implements FilenameFilter {

        public boolean accept(File dir, String file) {

            if (file == null) {
                throw new IllegalArgumentException();
            }
            int length = file.length();
            return length > 2 &&
                    file.charAt(length - 2) == '.' &&
                    file.charAt(length - 1) >= '0' &&
                    file.charAt(length - 1) <= '9';
        }
    }
