package fr.bmartel.android.apkchecker;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import sun.security.pkcs.PKCS7;
import Decoder.BASE64Encoder;

public class Main {

	public static String DEFAULT_FOLDER = "temp";

	public static void main(String[] args) throws IOException {

		boolean isList = false;
		boolean isVerify = false;
		boolean isCompare = false;

		boolean countingApk = false;

		List<ApkObject> apkList = new ArrayList<ApkObject>();

		if (args.length > 0) {

			for (int i = 0; i < args.length; i++) {
				if (args[i].equals("-l") || args[i].equals("-list")) {
					isList = true;
					countingApk = true;
				} else if (args[i].equals("-v") || args[i].equals("-verify")) {
					countingApk = false;
					isVerify = true;
				} else if (args[i].equals("-c") || args[i].equals("-comparePubkey")) {
					countingApk = false;
					isCompare = true;
				} else if (countingApk) {
					apkList.add(new ApkObject(args[i]));
				}
			}
		} else {
			dispalyUsage();
		}

		if (apkList.size() > 0) {

			if (isVerify) {
				for (int i = 0; i < apkList.size(); i++) {
					CheckJarIntegrity check = new CheckJarIntegrity();
					try {
						boolean status = check.verifyJar(apkList.get(i).getFilePath());

						if (status) {
							System.out.println("[APK CHECKER] " + apkList.get(i).getFilePath() + " verification [   OK   ]");
						} else {
							System.out.println("[APK CHECKER] " + apkList.get(i).getFilePath() + " verification [ FAILURE ]");
							return;
						}
					} catch (Exception e) {
						e.printStackTrace();
						return;
					}
				}
			}

			if (isCompare) {
				for (int i = 0; i < apkList.size(); i++) {
					try {
						extractCertFromApk(apkList.get(i).getFilePath());
						String publicKey = getPublicKey(DEFAULT_FOLDER + File.separator + "META-INF/CERT.RSA");
						apkList.get(i).setPublicKey(publicKey);
					} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
						e.printStackTrace();
						return;
					}
				}

				for (int i = 0; i < apkList.size(); i++) {
					if (i + 1 < apkList.size()) {
						if (!apkList.get(i).getPublicKey().equals(apkList.get(i + 1).getPublicKey())) {
							System.out.println("[APK CHECKER] apk public key not shared for " + apkList.get(i).getFilePath() + " and "
									+ apkList.get(i + 1).getFilePath() + " [ FAILURE ]");
							return;
						} else {
							System.out.println("[APK CHECKER] apk public key shared for " + apkList.get(i).getFilePath() + " and "
									+ apkList.get(i + 1).getFilePath() + " [    OK   ]");
						}
					}
				}
			}
			System.out.println("[APK CHECKER] Apks refer to the same Android application");
		} else {
			System.out.println("Error apk list is empty");
		}
	}

	/**
	 * Retrieve public key from PKCS7 certificate
	 * 
	 * @param certPath
	 * @return
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public static String getPublicKey(String certPath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

		File f = new File(certPath);
		FileInputStream is = new FileInputStream(f);

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[16384];

		while ((nRead = is.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}

		buffer.flush();
		PKCS7 test = new PKCS7(buffer.toByteArray());
		X509Certificate[] certs = test.getCertificates();

		for (int i = 0; i < certs.length; i++) {
			if (certs[i] != null && certs[i].getPublicKey() != null) {
				return new BASE64Encoder().encode(certs[i].getPublicKey().getEncoded());
			}
		}
		return "";
	}

	public static void extractCertFromApk(String apkFile) throws IOException {

		File file = new File(apkFile);

		File folder = new File(DEFAULT_FOLDER);
		if (!folder.exists()) {
			folder.mkdir();
		}

		ZipInputStream zipStream = new ZipInputStream(new FileInputStream(file));
		ZipEntry zipEntry = zipStream.getNextEntry();

		byte[] buffer = new byte[1024];

		while (zipEntry != null) {

			String fileName = zipEntry.getName();

			if (fileName.equals("META-INF/CERT.RSA")) {

				File newFile = new File(DEFAULT_FOLDER + File.separator + fileName);

				// create all non exists folders // else you will hit
				// FileNotFoundException for compressed folder
				new File(newFile.getParent()).mkdirs();

				FileOutputStream fos = new FileOutputStream(newFile);

				int len;
				while ((len = zipStream.read(buffer)) > 0) {
					fos.write(buffer, 0, len);
				}

				fos.close();

				break;
			}
			zipEntry = zipStream.getNextEntry();
		}

		zipStream.closeEntry();
		zipStream.close();

	}

	private static void dispalyUsage() {
		System.out.println("Usage               : java -jar apkChecker.jar -l <apks> <options>");
		System.out.println("-l / -list          : list of jars with separated with empty space(s)");
		System.out.println("-v / -verify        : verify java archive");
		System.out.println("-c / -comparePubkey : compare public keys of jars");
	}
}
