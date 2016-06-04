package eu.sipria.jwt

import javax.crypto.SecretKey

import eu.sipria.jwt.algorithms.JwtAlgorithm

case class TestObject(value: String) {
  override def toString: String = this.value
}

class JwtUtilsSpec extends UnitSpec with Fixture {

  describe("JwtUtils") {

    val message = """{"alg":"alg"}.{"user":1, "admin":true, "value":"foo"}"""

    it("should sign and verify signature correctly") {

      JwtAlgorithm.allHmac.foreach { alg =>
        val signature = JwtUtils.sign(
          message,
          JwtUtils.getSigningKeyFromBase64("1kHndxh2zXTK701QKx6B_CkzEu-orMR-TpvJXvlrjXg7maLf_1B7yegplt3EW9Mp", alg).asInstanceOf[SecretKey],
          alg
        )

        assertResult(true, "verify " + alg.fullName) {
          JwtUtils.verify(
            message.getBytes("UTF-8"),
            signature,
            JwtUtils.getVerifyKeyFromBase64("1kHndxh2zXTK701QKx6B_CkzEu-orMR-TpvJXvlrjXg7maLf_1B7yegplt3EW9Mp", alg),
            alg
          )
        }
      }

      JwtAlgorithm.allRSA.foreach { alg =>
        val signature = JwtUtils.sign(message, randomRSAKey.getPrivate, alg)

        assertResult(true, "verify " + alg.fullName) {
          JwtUtils.verify(message.getBytes("UTF-8"), signature, randomRSAKey.getPublic, alg)
        }
      }

      JwtAlgorithm.allECDSA.foreach { alg =>
        val signature = JwtUtils.sign(message, randomECKey.getPrivate, alg)

        assertResult(true, "verify " + alg.fullName) {
          JwtUtils.verify(message.getBytes("UTF-8"), signature, randomECKey.getPublic, alg)
        }
      }
    }


/*
    val signKey = Option("secret")
    val signMessage = """{"alg": "algo"}.{"user": 1, "admin": true, "value": "foo"}"""

    // Seq[(result, alg)]
    val signValues: Seq[(String, String)] = Seq(
      ("媉㶩஥ᐎ䗼ⲑΠ", "HmacMD5"),
      ("媉㶩஥ᐎ䗼ⲑΠ", "HMD5"),
      ("ﹰﱉ녙죀빊署▢륧婍", "HmacSHA1")
    )

    describe("sign byte array") {
      it("should correctly handle string") {
        signValues.foreach { value =>
          assertResult(value._1.getBytes(ENCODING)) { JwtUtils.sign(signMessage.getBytes(ENCODING), signKey, Option(value._2)) }
        }
      }
    }

    describe("sign string") {
      it("should correctly handle string") {
        signValues.foreach {
          value => assertResult(value._1.getBytes(ENCODING)) { JwtUtils.sign(signMessage, signKey, Option(value._2)) }
        }
      }
    }
*/
  }
}
