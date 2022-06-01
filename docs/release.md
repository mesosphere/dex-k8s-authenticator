# Releasing a new image version

1. Tag the commit you want to release (tags have historically followed the format: `v1.2.3-d2iq`)
2. The [release](../.github/workflows/release.yaml) GitHub action will build and push the image to DockerHub
