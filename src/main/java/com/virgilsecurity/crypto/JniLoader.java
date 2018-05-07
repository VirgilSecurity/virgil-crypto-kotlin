/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.crypto;

import java.io.*;

/**
 * .._  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    4/24/18
 * ...-| | \    at Virgil Security
 * ....|_|-
 */
public class JniLoader {

    private static final String MACOS_OS_NAME = "mac os";
    private static final String LINUX_OS_NAME = "linux";
    private static final String WINDOWS_OS_NAME = "windows";
    private static final String UNKNOWN_OS = "unknown";

    private static final String MACOS_LIBS_DIRECTORY = MACOS_OS_NAME;
    private static final String LINUX_LIBS_DIRECTORY = LINUX_OS_NAME;
    private static final String WINDOWS_LIBS_DIRECTORY = WINDOWS_OS_NAME;

    private static final String SEPARATOR = "/";

    static {
        try {
            loadNativeLibrary("virgil_crypto_java");
        } catch (Exception error) {
            System.err.println("Native code library failed to load. \n" + error);
        }
    }

    public static void loadNativeLibrary(String libraryName) throws IOException {

        try {
            System.loadLibrary(libraryName);
            // Library is loaded (Android or exists in java.library.path). We
            // can exit
            return;
        } catch (Throwable e) {
            // Library couldn't be loaded yet. We'll load it later.
        }

        // Build native library name according to current system
        String osName = System.getProperty("os.name").toLowerCase();
        String os = getOS(osName);
        String osArch = System.getProperty("os.arch").toLowerCase();

        StringBuilder resourceName = new StringBuilder();
        resourceName.append(getResourceDirectory(os, osArch)).append(SEPARATOR).append(libraryName);

        // Save native library as temporary file
        InputStream in = virgil_crypto_javaJNI.class.getClassLoader().getResourceAsStream(resourceName.toString());
        if (in == null) {
            throw new FileNotFoundException("Resource '" + resourceName.toString() + "' not found");
        }

        byte[] buffer = new byte[1024];
        int read = -1;
        File temp = File.createTempFile(libraryName, getLibraryFileSuffix(os));

        FileOutputStream fos = new FileOutputStream(temp);

        while ((read = in.read(buffer)) != -1) {
            fos.write(buffer, 0, read);
        }
        fos.close();
        in.close();

        System.load(temp.getAbsolutePath());
    }

    private static final String getLibraryFileSuffix(String os) {
        switch (os) {
            case LINUX_OS_NAME:
            case MACOS_OS_NAME:
                return ".so";
            case WINDOWS_OS_NAME:
                return ".dll";
        }
        return "";
    }

    /**
     * Get operation system by operation system name
     *
     * @param osName
     *            The OS name.
     * @return
     */
    private static final String getOS(String osName) {
        for (String os : new String[] { LINUX_OS_NAME, WINDOWS_OS_NAME, MACOS_OS_NAME }) {
            if (osName.startsWith(os)) {
                return os;
            }
        }
        return UNKNOWN_OS;
    }

    private static final String getResourceDirectory(String os, String osArch) {
        switch (os) {
            case LINUX_OS_NAME:
                return LINUX_LIBS_DIRECTORY;
            case MACOS_OS_NAME:
                return MACOS_LIBS_DIRECTORY;
            case WINDOWS_OS_NAME:
                return WINDOWS_LIBS_DIRECTORY + SEPARATOR + osArch;
        }
        return "";
    }
}
