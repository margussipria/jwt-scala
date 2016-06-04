package eu.sipria.jwt

import eu.sipria.jwt.algorithms.JwtAlgorithm
import eu.sipria.jwt.exceptions.JwtNonSupportedAlgorithm

class JwtAlgorithmSpec extends UnitSpec with Fixture {

  describe("JwtAlgorithm") {

    it("should find all algorithms") {

      (JwtAlgorithm.allHmac ++ JwtAlgorithm.allAsymmetric).foreach { alg =>
        JwtAlgorithm.optionFromString(alg.name) should be (Some(alg))
      }

      JwtAlgorithm.optionFromString("none") should be(None)
    }

    it("should throw exception if unknown algorithm is given") {

      intercept[JwtNonSupportedAlgorithm] { JwtAlgorithm.fromString("unknown") }.getMessage should be ("The algorithm [unknown] is not currently supported.")
    }
  }
}
