package pdi.jwt

import java.time.Instant

import mockit.{Mock, MockUp}

trait TimeFixture {
  def mockTime(now: Long) = {
    new MockUp[Instant]() {
      @Mock
      def toEpochMilli: Long = now
    }
  }
}
