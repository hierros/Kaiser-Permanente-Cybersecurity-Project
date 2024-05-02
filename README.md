# Threat View Project
## Purpose
This application serves as a visualization tool designed to extend the functionality of Splunk Enterprise by enabling cyber analysts to efficiently view cyberthreat data in a streamlined form.
## Description
This custom visualization tool is designed to be used with Splunk Enterprise. It has been designed based on the MITRE ATT&CK® Enterprise Matrix, which contains a comprehensive database of various tactics and techniques that have been utilized against enterprise-level systems across various platforms. The software is designed to work with cyberattack data, where each represented cyberattack is cataloged with the following information:  
* A title (can be blank)
* The MITRE tactic, technique, description, and coresponding technique ID that the cyberattack utilizes
* A timestamp.

In order for the visualization to work properly, you must ensure that the dataset you are using contains column headers that specify the fields listed above. The column headers must match the following exactly:
* The column containing the titles of each attack must have the header name '**title**'
* The column containing the tactic of each attack must have the header name '**tactic**'
* The column containing the technique of each attack must have the header name '**technique**'
* The column containing the technique ID of each attack must have the header name '**technique_id**'
* The column containing the description of each attack must have the header name '**description**'
* The column containing the timestamp of each attack must have the header name '**_time**'   

The visualization allows for the data to be represented in two distinct views. The default view is the "Tactic View," in which the x-axis of the visualization is based on the various MITRE ATT&CK® database tactics that are present within the data, and each cyberattack is sorted into a "tactic column" based on the tactic of the cyberattack. The second view is the "Timeline View." In this view, the cyberattacks are arranged based on their timestamps. By allowing a user to switch their selected view, they can customize the product to fit their individual use case.  

## GitHub Directory  
### **Documentation Folder**

#### **Future Work for Threat View -** 
This document contains a list of potential improvements identified by either the team or testers during the testing phase that were unable to be made during the semester due to time constraints.  

#### **Requirements Document -** 
This document contains a detailed outline of the product's purpose, features, and required elements. It has been annotated to indicate which features are working as defined in the document.  

#### **Design and Model Diagrams -** 
This subfolder contains preliminary design items, such as the original card design as well as mockups of the original tactic and timeline views.    

#### **Meetings Records -** 
This subfolder contains information related to meetings. Summaries of all meetings, including information about decisions made during these meetings, can be found here.  

#### **Older Documentations -** 
This subfolder contains old versions of the requirements and instructions documents that are not currently in use.  

#### **Reference Data -** 
This subfolder contains cyberattack data used for testing purposes, as well as spreadsheet versions of the MITRE ATT&CK database.  

#### **Testing Items -** 
This subfolder contains items from user testing, including testing results and instructions.


### **Old App Versions Folder -**
This folder contains older versions of the application, should you need to review them.  


### **Threat Timeline -** 
This folder contains the source code for the visualization itself. The zip folder contains the same code.

### **Threat_Timeline.tar and Threat_Timeline.tar.gz -**  
This is the application in a format that can be given directly to Splunk® Enterprise for installation.

## Intended Users  
This product is intended to be used by those with a cybersecurity background who have experience with Splunk Enterprise to display threats captured by an external system. Since this product does not capture data itself, the user must have access to pre-captured data in order to utilize the visualization.

## Original Authors
**Noah Warren - noahwarren118@gmail.com**  
**Danae O'Connor - danae.oconnor@ucdenver.edu**  
## Project Dependencies and Technologies Used    
This project has been designed for and tested to work with Splunk® Enterprise up to version 9.2.0.1. Compatibility with later versions of Splunk® is not guaranteed.
Compatibility is also not guaranteed for Splunk® Cloud.

This product utilizes D3.js version 3.1.4 in order to create the custom visualization. More information on D3.js can be found below under "Resources."

This application also utilizes node package manager (npm). In order to modify the product, you will need to install npm. It is recommended to do this through the use of node version manger (nvm). If you need help installing nvm, a link to the GitHub page has been provided below under "Resources."

## Safety  
All data presented within the visualization will be provided by the user via Splunk Enterprise. This visualization is designed to work specifically with cyberattacks that are defined within the MITRE ATT&CK database. The data presented in the visualization is not duplicated or shared in any way. With this in mind, please use this product wisely and do not share confidential data with any non-authorized parties.

## Resources
- [Splunk Custom Visualization Tutorial](https://docs.splunk.com/Documentation/SplunkCloud/9.1.2312/AdvancedDev/CustomVizTutorial)  
- [MITRE ATT&CK® Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)  
- [D3.js](https://d3js.org/)  
- [Information on D3.js for Splunk ](https://docs.splunk.com/Documentation/ContentPackApp/2.1.0/ReleaseNotes/D3)  
- [Node Version Manager (nvm)](https://github.com/nvm-sh/nvm)