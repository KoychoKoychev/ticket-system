# ticket-system

Codebase for an Encrypted Ticket System.

## What packages do we include?
1. ``api`` - This contains the web server that receives and saves all the created tickets in a database
2. ``client`` - This is the package that can be included in other repositories in order to communicate with the API. It handles the composition and encryption of the tickets and also the requests to the api.

## Why in one folder?
All of the packages that are included are strictly dependent on each other. In order to avoid issues with mixing the versions of the separate packages, we keep them in one place and one joint state.

## Can we use the packages separately?
Each package can be used separately even though it is dependent on the rest. 