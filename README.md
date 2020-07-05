# VTIL-BinaryNinja
VTIL meets Binary Ninja and provides you with a solution to analyze VTIL code in a less painful manner.

## Installation
Install via the Plugin Manager in Binary Ninja, or clone this repository into your [plugin folder](https://docs.binary.ninja/guide/plugins.html#using-plugins).  
Note: If you default to an IL view, you will need to manually make sure you select an Assembly view as this plugin does not have any lifting at this time.

## Screenshots
![](images/example.png)

## Dislcaimer
This is a **very early proof of concept**. Expect bugs.  

Known issues:
- If multiple VTIL files are open, switching tabs to one with a lot of content can cause Binary Ninja to crash
- Goto labels are not clickable
