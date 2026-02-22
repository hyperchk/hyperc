const crypto = require("crypto");
const fs = require("fs");

try {

    const password = "cesaralonsoapolayapacheco";
    const content = fs.readFileSync("real.html", "utf8");

    console.log("Content length:", content.length);

    const key = crypto.createHash("sha256").update(password).digest();
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    const encrypted = Buffer.concat([cipher.update(content), cipher.final()]);

    const hmac = crypto.createHmac("sha256", key).update(encrypted).digest();

    const final = Buffer.concat([iv, hmac, encrypted]);

    console.log("Final length:", final.length);

    console.log(final.toString("base64"));

} catch (err) {
    console.error("ERROR:", err);
}