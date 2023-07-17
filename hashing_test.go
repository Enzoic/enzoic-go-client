package enzoic

import (
	"log"
	"testing"

	"gopkg.in/stretchr/testify.v1/assert"
)

func TestCalcArgon2(t *testing.T) {
	result, _ := CalcArgon2("123456", "saltysalt")
	assert.Equal(t, result, "12494620fb424966f7212faae0843baf0af09b6a")

	result2, _ := CalcArgon2("enz_eicar2$49efef5f70d47adc2db2eb397fbef5f7bc560e29", "k8=3W_hux:Tn{U}q!-CQxY+N(Z9PFe#Z")
	assert.Equal(t, result2, "0922b87d3e71f10030b49c8ce721e6b226b935ab")

	result3, _ := CalcArgon2("eicar_1@enzoic.com$e10adc3949ba59abbe56e057f20f883e", "r:sNmYdWHp+]wO.6?24xAqX:U|eo[6RF")
	assert.Equal(t, result3, "38f7e43187a8d1ac386007f88c91a763dd983e31")
}

func TestBcrypt(t *testing.T) {
	result, err := CalcBCrypt("12345", "$2a$12$2bULeXwv2H34SXkT1giCZe")
	if err == nil {
		assert.Equal(t, "$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm", result)
	} else {
		log.Fatal(err)
	}

	//Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.BCrypt, "12345", "$2a$12$2bULeXwv2H34SXkT1giCZe"), "$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm");
}

func TestCalcPasswordHash(t *testing.T) {
	assert.Equal(t, "e10adc3949ba59abbe56e057f20f883e", CalcPasswordHashForTest(MD5, "123456", ""))
	assert.Equal(t, "32ed87bdb5fdc5e9cba88547376818d4", CalcPasswordHashForTest(NTLM, "123456", ""))
	assert.Equal(t, "7c4a8d09ca3762af61e59520943dc26494f8941b", CalcPasswordHashForTest(SHA1, "123456", ""))
	assert.Equal(t, "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", CalcPasswordHashForTest(SHA256, "123456", ""))
	assert.Equal(t, "0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454", CalcPasswordHashForTest(SHA384, "123456", ""))
	assert.Equal(t, "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413", CalcPasswordHashForTest(SHA512, "123456", ""))
	assert.Equal(t, "$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm", CalcPasswordHashForTest(BCrypt, "12345", "$2a$12$2bULeXwv2H34SXkT1giCZe"))
	assert.Equal(t, "55566a759b86fbbd979b579b232f4dd214d08068", CalcPasswordHashForTest(SHA1Dash, "123456", "478c8029d5efddc554bf2fe6bb2219d8c897d4a0"))
	assert.Equal(t, "901924565", CalcPasswordHashForTest(CRC32, "password", ""))
	assert.Equal(t, "cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206", CalcPasswordHashForTest(CustomAlgorithm1, "123456", "00new00"))
	assert.Equal(t, "579d9ec9d0c3d687aaa91289ac2854e4", CalcPasswordHashForTest(CustomAlgorithm2, "123456", "123"))
	assert.Equal(t, "96c06579d8dfc66d81f05aab51a9b284", CalcPasswordHashForTest(IPBoard_MyBB, "123456", "12345"))
	assert.Equal(t, "$H$993WP3hbzy0N22X06wxrCc3800D2p41", CalcPasswordHashForTest(PHPBB3, "123456789", "$H$993WP3hbz"))
	assert.Equal(t, "77d3b7ed9db7d236b9eac8262d27f6a5", CalcPasswordHashForTest(vBulletinPost3_8_5, "123456", "123"))
	assert.Equal(t, "77d3b7ed9db7d236b9eac8262d27f6a5", CalcPasswordHashForTest(vBulletinPre3_8_5, "123456", "123"))
	assert.Equal(t, "$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.", CalcPasswordHashForTest(MD5Crypt, "123456", "$1$4d3c09ea"))
	assert.Equal(t, "$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W", CalcPasswordHashForTest(CustomAlgorithm4, "1234", "$2y$12$Yjk3YjIzYWIxNDg0YWMzZO"))
	assert.Equal(t, "69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163", CalcPasswordHashForTest(CustomAlgorithm5, "password", "123456"))
	assert.Equal(t, "d2bc2f8d09990ebe87c809684fd78c66", CalcPasswordHashForTest(osCommerce_AEF, "password", "123"))
	assert.Equal(t, "yDba8kDA7NUDQ", CalcPasswordHashForTest(DESCrypt, "qwerty", "yD"))
	assert.Equal(t, "X.OPW8uuoq5N.", CalcPasswordHashForTest(DESCrypt, "password", "X."))
	assert.Equal(t, "5d2e19393cc5ef67", CalcPasswordHashForTest(MySQLPre4_1, "password", ""))
	assert.Equal(t, "*94bdcebe19083ce2a1f959fd02f964c7af4cfc29", CalcPasswordHashForTest(MySQLPost4_1, "test", ""))
	assert.Equal(t, "3weP/BR8RHPLP2459h003IgJxyU=", CalcPasswordHashForTest(PeopleSoft, "TESTING", ""))
	assert.Equal(t, "0c9a0dc3dd0b067c016209fd46749c281879069e", CalcPasswordHashForTest(PunBB, "password", "123"))
	assert.Equal(t, "5f4dcc3b5aa765d61d83", CalcPasswordHashForTest(PartialMD5_20, "password", ""))
	assert.Equal(t, "5f4dcc3b5aa765d61d8327deb882c", CalcPasswordHashForTest(PartialMD5_29, "password", ""))
	assert.Equal(t, "696d29e0940a4957748fe3fc9efd22a3", CalcPasswordHashForTest(AVE_DataLife_Diferior, "password", ""))
	assert.Equal(t, "md5$c6218$346abd81f2d88b4517446316222f4276", CalcPasswordHashForTest(DjangoMD5, "password", "c6218"))
	assert.Equal(t, "sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845", CalcPasswordHashForTest(DjangoSHA1, "password", "c6218"))
	assert.Equal(t, "1230de084f38ace8e3d82597f55cc6ad5d6001568e6", CalcPasswordHashForTest(PliggCMS, "password", "123"))
	assert.Equal(t, "0de084f38ace8e3d82597f55cc6ad5d6001568e6", CalcPasswordHashForTest(RunCMS_SMF1_1, "password", "123"))
	assert.Equal(t, "a753d386613efd6d4a534cec97e73890f8ec960fe6634db6dbfb9b2aab207982", CalcPasswordHashForTest(CustomAlgorithm7, "123456", "123456"))
	assert.Equal(t, "9fc389447b7eb88aff45a1069bf89fbeff89b8fb7d11a6f450583fa4c9c70503", CalcPasswordHashForTest(CustomAlgorithm8, "matthew", "Dn"))
	assert.Equal(t, "07c691fa8b022b52ac1c44cab3e056b344a7945b6eb9db727e3842b28d94fe18c17fe5b47b1b9a29d8149acbd7b3f73866cc12f0a8a8b7ab4ac9470885e052dc", CalcPasswordHashForTest(CustomAlgorithm9, "0rangepeel", "6kpcxVSjagLgsNCUCr-D"))
	assert.Equal(t, "bd17b9d14010a1d4f8c8077f1be1e20b9364d9979bbcf8591337e952cc6037026aa4a2025543d39169022344b4dd1d20f499395533e35705296034bbf7e7d663", CalcPasswordHashForTest(CustomAlgorithm10, "chatbooks", "NqXCvAHUpAWAco3hVTG5Sg0FfmJRQPKi0LvcHwylzXHhSNuWwvYdMSSGzswi0ZdJ"))
	assert.Equal(t, "d89c92b4400b15c39e462a8caa939ab40c3aeeea", CalcPasswordHashForTest(HMACSHA1_SaltAsKey, "hashcat", "1234"))
	assert.Equal(t, "$5$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", CalcPasswordHashForTest(SHA256Crypt, "hashcat", "$5$GX7BopJZJxPc/KEK"))
	assert.Equal(t, "$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", CalcPasswordHashForTest(SHA512Crypt, "hashcat", "$6$52450745"))
	assert.Equal(t, "$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824", CalcPasswordHashForTest(AuthMeSHA256, "hashcat", "7218532375810603"))

}

func CalcPasswordHashForTest(passwordType PasswordType, password string, salt string) string {
	result, err := CalcPasswordHash(passwordType, password, salt)
	if err != nil {
		log.Fatal(err)
	}
	return result
}
