package fr.bmartel.android.apkchecker;

public class ApkObject {

	private String filePath = "";

	private String publicKey = "";

	public ApkObject(String filePath) {
		this.filePath = filePath;
	}

	public String getFilePath() {
		return filePath;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}
}
