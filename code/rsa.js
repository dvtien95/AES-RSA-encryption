// Generate key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
})

console.log(
	publicKey.export({
		type: "pkcs1",
		format: "pem",
	}),

	privateKey.export({
		type: "pkcs1",
		format: "pem",
	})
)

// Encrypt data
const data = "some data"
const encryptedData = crypto.publicEncrypt(
	{
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: "sha256",
	},

	Buffer.from(data)
)

console.log("encypted data: ", encryptedData.toString("base64"))


const decryptedData = crypto.privateDecrypt(
	{
		key: privateKey,

		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: "sha256",
	},
	encryptedData
)

console.log("decrypted data: ", decryptedData.toString())


const verifiableData = "verify signature"


const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
	key: privateKey,
	padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
})

console.log(signature.toString("base64"))


const isVerified = crypto.verify(
	"sha256",
	Buffer.from(verifiableData),
	{
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
	},
	signature
)

console.log("signature: ", isVerified)