publishTo <<= version { version: String =>
  if (version.trim.endsWith("SNAPSHOT")) {
    Some("Sonatype Nexus Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots")
  } else {
    Some("Sonatype Nexus Staging" at "https://oss.sonatype.org/service/local/staging/deploy/maven2")
  }
}

useGpg := true
