package eu.sipria.jwt

import java.time.Instant

import eu.sipria.jwt.exceptions.{JwtExpirationException, JwtNotBeforeException}

/** Util object to handle time operations */
class JwtTime {
  /** Returns the number of seconds since the 01.01.1970
    *
    * @return Returns the number of seconds since the 01.01.1970
    */
  def now: Long = Instant.now().getEpochSecond

  /** Test if the current time is between the two params and throw an exception if we don't have `start` <= now < `end`
    *
    * @param start if set, the instant that must be before now (in seconds)
    * @param end   if set, the instant that must be after now (in seconds)
    * @throws JwtNotBeforeException  if `start` > now
    * @throws JwtExpirationException if now >= `end`
    */
  def validateNowIsBetween(start: Option[Long], end: Option[Long]): Boolean = {
    val timeNow = now

    if (start.isDefined && start.get > timeNow) {
      throw new JwtNotBeforeException(start.get)
    }

    if (end.isDefined && timeNow >= end.get) {
      throw new JwtExpirationException(end.get)
    }

    true
  }

  /** Test if the current time is between the two prams
    *
    * @return the result of the test
    * @param start if set, the instant that must be before now (in seconds)
    * @param end   if set, the instant that must be after now (in seconds)
    */
  def isNowIsBetween(start: Option[Long], end: Option[Long]): Boolean = {
    try {
      validateNowIsBetween(start, end)
    } catch {
      case _: JwtNotBeforeException => false
      case _: JwtExpirationException => false
    }
  }
}

object JwtTime {
  def apply(): JwtTime = new JwtTime

  def format(time: Long): String = Instant.ofEpochSecond(time).toString
}
