package fr.bmartel.android.apkchecker;

/*
 * Copyright 1997-2007 Sun Microsystems, Inc.  All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Sun designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Sun in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 */

import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import sun.security.x509.NetscapeCertTypeExtension;

public final class CheckJarIntegrity {

	private boolean hasExpiredCert = false;

	private boolean hasExpiringCert = false;

	private boolean showcerts = false;

	private boolean badKeyUsage = false;

	private boolean badExtendedKeyUsage = false;

	private boolean badNetscapeCertType = false;

	private boolean notYetValidCert = false;

	private static final long SIX_MONTHS = 180 * 24 * 60 * 60 * 1000L;

	private static final String META_INF = "META-INF/";

	// prefix for new signature-related files in META-INF directory
	private static final String SIG_PREFIX = META_INF + "SIG-";

	public boolean verifyJar(String jarName) throws Exception {
		boolean anySigned = false;
		boolean hasUnsignedEntry = false;
		JarFile jf = null;

		try {
			jf = new JarFile(jarName, true);
			Vector<JarEntry> entriesVec = new Vector<JarEntry>();
			byte[] buffer = new byte[8192];

			Enumeration<JarEntry> entries = jf.entries();
			while (entries.hasMoreElements()) {
				JarEntry je = entries.nextElement();
				entriesVec.addElement(je);
				InputStream is = null;
				try {
					is = jf.getInputStream(je);
					int n;
					while ((n = is.read(buffer, 0, buffer.length)) != -1) {
						// we just read. this will throw a SecurityException
						// if a signature/digest check fails.
					}
				} finally {
					if (is != null) {
						is.close();
					}
				}
			}

			Manifest man = jf.getManifest();

			if (man != null) {
				Enumeration<JarEntry> e = entriesVec.elements();

				long now = System.currentTimeMillis();

				while (e.hasMoreElements()) {
					JarEntry je = e.nextElement();
					String name = je.getName();
					CodeSigner[] signers = je.getCodeSigners();

					boolean isSigned = (signers != null);
					anySigned |= isSigned;
					hasUnsignedEntry |= !je.isDirectory() && !isSigned && !signatureRelated(name);

					if (isSigned) {
						for (int i = 0; i < signers.length; i++) {
							Certificate cert = signers[i].getSignerCertPath().getCertificates().get(0);

							if (cert instanceof X509Certificate) {

								checkCertUsage((X509Certificate) cert, null);

								if (!showcerts) {
									long notAfter = ((X509Certificate) cert).getNotAfter().getTime();

									if (notAfter < now) {
										hasExpiredCert = true;
									} else if (notAfter < now + SIX_MONTHS) {
										hasExpiringCert = true;
									}
								}
							}
						}
					}

				}
			}

			if (man == null)
				System.out.println("no manifest.");

			if (!anySigned) {
				System.out.println("jar is unsigned. (signatures missing or not parsable)");
			} else {
				System.out.println("jar verified.");
				if (hasUnsignedEntry || hasExpiredCert || hasExpiringCert || badKeyUsage || badExtendedKeyUsage || badNetscapeCertType || notYetValidCert) {

					System.out.println();
					System.out.println("Warning: ");
					if (badKeyUsage) {
						System.out.println("This jar contains entries whose signer certificate's KeyUsage extension doesn't allow code signing.");
					}
					if (badExtendedKeyUsage) {
						System.out.println("This jar contains entries whose signer certificate's ExtendedKeyUsage extension doesn't allow code signing.");
					}
					if (badNetscapeCertType) {
						System.out.println("This jar contains entries whose signer certificate's NetscapeCertType extension doesn't allow code signing.");
					}
					if (hasUnsignedEntry) {
						System.out.println("This jar contains unsigned entries which have not been integrity-checked. ");
					}
					if (hasExpiredCert) {
						System.out.println("This jar contains entries whose signer certificate has expired. ");
					}
					if (hasExpiringCert) {
						System.out.println("This jar contains entries whose signer certificate will expire within six months. ");
					}
					if (notYetValidCert) {
						System.out.println("This jar contains entries whose signer certificate is not yet valid. ");
					}
				}
				return true;
			}
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("jarsigner: " + e);
		} finally { // close the resource
			if (jf != null) {
				jf.close();
			}
		}

		return false;
	}

	private boolean signatureRelated(String name) {
		String ucName = name.toUpperCase();
		if (ucName.equals(JarFile.MANIFEST_NAME) || ucName.equals(META_INF)
				|| (ucName.startsWith(SIG_PREFIX) && ucName.indexOf("/") == ucName.lastIndexOf("/"))) {
			return true;
		}

		if (ucName.startsWith(META_INF) && isBlockOrSF(ucName)) {

			// .SF/.DSA/.RSA files in META-INF subdirs
			// are not considered signature-related
			return (ucName.indexOf("/") == ucName.lastIndexOf("/"));
		}

		return false;
	}

	private boolean isBlockOrSF(String s) {
		// we currently only support DSA and RSA PKCS7 blocks
		if (s.endsWith(".SF") || s.endsWith(".DSA") || s.endsWith(".RSA")) {

			return true;
		}
		return false;
	}

	private void checkCertUsage(X509Certificate userCert, boolean[] bad) {

		// Can act as a signer?
		// 1. if KeyUsage, then [0] should be true
		// 2. if ExtendedKeyUsage, then should contains ANY or CODE_SIGNING
		// 3. if NetscapeCertType, then should contains OBJECT_SIGNING
		// 1,2,3 must be true

		if (bad != null) {
			bad[0] = bad[1] = bad[2] = false;
		}

		boolean[] keyUsage = userCert.getKeyUsage();
		if (keyUsage != null) {
			if (keyUsage.length < 1 || !keyUsage[0]) {
				if (bad != null) {
					bad[0] = true;
				} else {
					badKeyUsage = true;
				}
			}
		}

		try {
			List<String> xKeyUsage = userCert.getExtendedKeyUsage();
			if (xKeyUsage != null) {
				if (!xKeyUsage.contains("2.5.29.37.0") // anyExtendedKeyUsage
						&& !xKeyUsage.contains("1.3.6.1.5.5.7.3.3")) { // codeSigning
					if (bad != null) {
						bad[1] = true;
					} else {
						badExtendedKeyUsage = true;
					}
				}
			}
		} catch (java.security.cert.CertificateParsingException e) {
			// shouldn't happen
		}

		try {
			// OID_NETSCAPE_CERT_TYPE
			byte[] netscapeEx = userCert.getExtensionValue("2.16.840.1.113730.1.1");
			if (netscapeEx != null) {
				DerInputStream in = new DerInputStream(netscapeEx);
				byte[] encoded = in.getOctetString();
				encoded = new DerValue(encoded).getUnalignedBitString().toByteArray();

				NetscapeCertTypeExtension extn = new NetscapeCertTypeExtension(encoded);

				Boolean val = (Boolean) extn.get(NetscapeCertTypeExtension.OBJECT_SIGNING);
				if (!val) {
					if (bad != null) {
						bad[2] = true;
					} else {
						badNetscapeCertType = true;
					}
				}
			}
		} catch (IOException e) {
			//
		}
	}
}