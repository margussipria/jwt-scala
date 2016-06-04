package eu.sipria.jwt

trait JsonDataEntryTrait[J] extends DataEntryBase {
  def headerJson: J
}

trait JsonCommonFixture[J] extends Fixture {
  implicit def jwtJson: JwtCore[J]

  def claimJson: J
  def headerEmptyJson: J
  def mapData(data: DataEntryBase): JsonDataEntryTrait[J]

  lazy val claimClass: JwtClaim[J] = claimClassString.copy(content = jwtJson.parse(claimClassString.content))

  val dataJson = data.map(mapData)
  val dataRSAJson = dataRSA.map(mapData)
  val dataECDSAJson = dataECDSA.map(mapData)
}
