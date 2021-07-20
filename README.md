# http

This is a Mythic C2 Profile called http. It simply provides a way to get HTTP messages off the wire and forward them to the Mythic server. This profiles includes:

* Kill Dates
* Sleep Intervals
* Custom Headers
* Proxy Information
* Support for SSL

The c2 profile has `mythic_c2_container==0.0.23` PyPi package installed and reports to Mythic as version "4".

## How to install an agent in this format within Mythic

When it's time for you to test out your install or for another user to install your c2 profile, it's pretty simple. Within Mythic you can run the `mythic-cli` binary to install this in one of three ways:

* `sudo ./mythic-cli install github https://github.com/user/repo` to install the main branch
* `sudo ./mythic-cli install github https://github.com/user/repo branchname` to install a specific branch of that repo
* `sudo ./mythic-cli install folder /path/to/local/folder/cloned/from/github` to install from an already cloned down version of an agent repo

Now, you might be wondering _when_ should you or a user do this to properly add your profile to their Mythic instance. There's no wrong answer here, just depends on your preference. The three options are:

* Mythic is already up and going, then you can run the install script and just direct that profile's containers to start (i.e. `sudo ./mythic-cli c2 start profileName`.
* Mythic is already up and going, but you want to minimize your steps, you can just install the profile and run `sudo ./mythic-cli mythic start`. That script will first _stop_ all of your containers, then start everything back up again. This will also bring in the new profile you just installed.
* Mythic isn't running, you can install the script and just run `sudo ./mythic-cli mythic start`. 
