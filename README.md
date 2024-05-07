# Vulntron

Vulntron is a Go-based application designed to work with OpenShift clusters and DefectDojo for vulnerability management and reporting. 
It's goal is to scan namespaces within given cluster, and analyze each pods images. When new image is deployed its SBOM is analyzed and report uploaded to the DefectDojo. 

The Vulntron tool is modular and it is possible to import more types of scans for each image. 

## Prerequisites
 
 - GO version 1.21.8 or newer
 - Access to openshift cluster for scanning
 - Updated config file with specific values 
 - Environment variables set: 
    1. **DefectDojo Credentials**:
        - `DEFECT_DOJO_USERNAME`: Your DefectDojo username
        - `DEFECT_DOJO_PASSWORD`: Your DefectDojo password
        - `DEFECT_DOJO_URL`: The URL to your DefectDojo instance
        - `DEFECT_DOJO_SLACK_CHANNEL`: The slack channel that should receive the notifications
        - `DEFECT_DOJO_SLACK_OAUTH`: The slack oauth token

    2. **OpenShift Token**:
        - `OC_TOKEN`: Environment variable with your OpenShift access token.

    3. **Kafka Configuration**:
        - `KAFKA_BROKER`: The address of your Kafka broker
        - `KAFKA_TOPIC`: The Kafka topic to subscribe to
        - `KAFKA_CONSUMER_GROUP`: The consumer group ID

## DefectDojo

The DefectDojo reporting portal should be deployed either by deploying it from Helm chart or by using the steps provided inside 
the the [product security DefectDojo](https://gitlab.cee.redhat.com/product-security/secaut/defectdojo-deployment) project repository. 

### DefectDojo Internal Setup

Using credentials provided via environment variables, the Vulntron tool will request an API token from the specified URL. After successful API token retrieval, all subsequent API calls will use this token.

The `config.yaml` file contains a section `defect_dojo` for configuring the DefectDojo reporting system. This configuration should be set before each scanning session to ensure the desired behavior. The complete Default DefectDojo reporting system configuration is shown below:

```json
{
  "defect_dojo": {
    "enable_deduplication": true,
    "delete_duplicates": true,
    "max_duplicates": 0,
    "slack_notifications": true
  }
}
```

All currently used system settings options are available using the UI system settings configuration by navigating to the System Settings page or using an API call to `GET /api/v2/system_settings/` endpoint.

The settings that are set by default using the Vulntron tool are:
- **enable_deduplication** - Enable finding duplicate vulnerabilities after importing automatically by the DefectDojo reporting system.
- **delete_duplicates** - Found duplicate vulnerabilities will be removed.
- **max_duplicates** - Number of duplicates to keep before deleting.
- **slack_notifications** - Switch to enable sending Slack notifications.

Adding new system settings for the DefectDojo reporting system requires updating the section above in `config.yaml` and updating the function `UpdateSystemSettings()` within the `vulntron_dd.go` file to include the newly added configuration.

### Internal Notifications
The notification (alerts in terms of the DefectDojo reporting system) are enabled by default and can be manually configured using the UI interface by navigating to `Settings -> Notifications` on the sidebar.

### Slack Integration
Slack integration must be installed as an application in the selected Slack workspace following the DefectDojo reporting system Slack integration tutorial [Configure a Slack Integration](https://support.defectdojo.com/en/articles/8944899-configure-a-slack-integration).

The types of selected notifications that should be received and also the types of alerts that should be shown inside the DefectDojo reporting system is configurable by navigating to `Settings -> Notifications`.

The types of notifications are customizable for individual users, but for the use case of the Vulntron tool, the `System` notification settings should be changed.

After the Slack notification on-boarding, the automatic step in the scanning pipeline takes care of checking the System Settings of the DefectDojo reporting tool, and if the settings were changed, they are automatically updated to match the configuration from environment variables.


### Modularity

Through the following steps, the new scanning tool may be imported into the Vulntron tool which makes it easier to automate the execution of scans and loading the results into the DefectDojo reporting portal. The steps are as follows:

- Add necessary configuration for the new scanning tool into `config.yaml` file.
- Create entry inside the `config.yaml` file within `scan_types` list in the format:

  - **name** (string) Name of the scan type compatible with the DefectDojo supported scan types [DefectDojo Parsers](https://defectdojo.github.io/django-DefectDojo/integrations/parsers/file/).
  - **engName** (string) Name of the imported engagement, should be clear what type of scans this engagement contains, no strict naming rules.
  - **function** (string) The name of the scanning function that must be imported into the `vulntron_auto.go` file and must match the schema:
    ``` go
    // Scan function signature.
    func RunTrivy(cfg config.Config, imageID string) (string, error)
    ```
    This function should accept two arguments: configuration (which could require adjustments in other configuration structures within `config.yaml`) and `imageID` (a string containing data about the image to be scanned).
    The function must return either an error, if the scanning or any setup steps fail, or a string that specifies the path to the scan results.
  - **enabled** (bool) Switch that disable the scan type from being executed.
    ```json
    // Scan type import example.
    {
    "scan_types": [
        {
        "name": "Anchore Grype",
        "engName": "Grype_eng",
        "function": "RunGrype",
        "enabled": true
        },
        {
        "name": "Scan name",
        "engName": "Engagement name",
        "function": "Scan function name",
        "enabled": true/false
        }
    ]
    }
    ```
- Add the entry into `scanFunctionMap` that will map the real function to the one from configuration file:
    ``` go
    // Scan function map example.
    var scanFunctionMap = map[string]ScanFunction{
        "RunGrype": vulntron_grype.RunGrype,
        // "RunAnotherScanner": vulntron_other.RunAnotherScanner
    }
    ```

If all steps are correctly implemented, the automated scan should recognize the new scan type and execute the scan on the selected images, and import the results of the scanning under the selected engagement name within each scanned namespace.


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

To cleanup the whole database build cleaning binary:

```bash
$ build-clean-db 
```
 and run the cleaning script:

```bash 
$  ./bin/clean_dd_db 
```


## Red Hat OpenShift Setup

Steps to set up and install the Vulntron tool in the Red Hat OpenShift cluster are similar to the local setup:

1. Create a new namespace that will store the Pods of the Vulntron tool and the DefectDojo report portal.
2. Install the DefectDojo reporting system on the desired cluster in the newly created Vulntron namespace. Installation may be done using Helm charts [Helm charts](https://github.com/DefectDojo/django-DefectDojo/tree/dev/helm/defectdojo) or any other method mentioned in the installation guide [Installation guide](https://defectdojo.github.io/django-DefectDojo/getting_started/installation/).
3. Get access to user/service account token that has cluster access at the level of listing the Pods and accessing the secrets needed.
4. Set up the secrets containing all the environment variables.
5. Edit the last line of the provided `Dockerfile` in the project root with the time interval that the Vulntron tool should run in. The default value is 1 hour.
6. Update the second part of the `Dockerfile` to contain the binaries needed for the additional scanners besides Grype, if they use not only Go libraries but also CLI tools.
7. Build the Vulntron tool image using the provided `Dockerfile`. The `Dockerfile` will firstly build the binary using the `golang:alpine` image that contains all the needed binaries. After the binary is built the whole project is copied to an `alpine` image and this process will greatly reduce the size of the image from 2GB+ to less than 200MB.
8. Tag and store the created image on an image storage platform (e.g., Quay.io).
9. Edit the `deployment.yaml` file in the project root to match the created secrets from step 4 and specify the path to the Vulntron tool image.
10. Log into the Red Hat OpenShift cluster from the local terminal and select the working Vulntron namespace with the DefectDojo reporting system running.
11. Deploy the Vulntron tool to the Red Hat OpenShift cluster using the command `oc apply -f deployment.yaml`.
