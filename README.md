# Vulntron

Vulntron is a Go-based application designed to work with OpenShift clusters and DefectDojo for vulnerability management and reporting. 
It's goal is to scan namespaces within given cluster, and analyze each pods images. When new image is deployed its SBOM is analyzed and report uploaded to defect dojo. 

## Prerequisites
 
 - GO version 1.21.8 or newer
 - Access to openshift cluster for scanning
 - Updated config file with specific values 
 - Environment variables set: 
    1. **DefectDojo Credentials**:
        - `DEFECT_DOJO_USERNAME`: Your DefectDojo username
        - `DEFECT_DOJO_PASSWORD`: Your DefectDojo password
        - `DEFECT_DOJO_URL`: The URL to your DefectDojo instance

    2. **OpenShift Token**:
        - `OC_TOKEN`: Environment variable with your OpenShift access token.

    3. **Kafka Configuration**:
        - `KAFKA_BROKER`: The address of your Kafka broker
        - `KAFKA_TOPIC`: The Kafka topic to subscribe to
        - `KAFKA_CONSUMER_GROUP`: The consumer group ID

## Configuration


## Build 

Provided makefile should be used to build the app.

``` bash
$ make build
```

## Usage

The app may be run from build binary: 

``` bash
$ ./bin/vulntron --config config.yaml
```
