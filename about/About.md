# About This Project

This project was started with a few things in mind:

- I wanted a portfolio to secure a job
- I decided that the portfolio should be extensible and modifiable
- I decided that I would opensource the portfolio
- I decided that I would build the portfolio with AI to demonstrate agentic development
- I decided that the portfolio would be cheap to host
- I decided that the portfolio should aim to be portable across hosting architectures

At the time of publishing this document, I have worked for ~1 week with AI agents to implement a Version 0 of this project.
The portability is still somewhat basic (host a react, ruby on rails, or go wasm app on aws, gcp, azure, or oci) and the full compatibility matrix is not fully tested.
However, all of the desired functionality is there, and any missing functionality (other types of apps) is very easy to add in.
Any project in the portfolio can be refreshed independently, requiring zero downtime for changes that are not to the portfolio code itself.
The portfolio can also be refreshed independently and recover state without affecting the other projects.
The portfolio interaction is clean, and is also highly modifiable.
Everything in the repo outside of this directory is written by AI, and then modified by me as desired.

# Next Steps

The only thing that sets this current version apart from the future Version 1 is testing/fixing the full compatibility matrix, and cleaning up the code for maintainability.

# Licensing

This project is licensed under the MIT license.

A code scan for licenses was done via scancode-toolkit and the output is in portfolio.json.

npx license-checker output is in npmLicenseScan.txt.

Note that the scan shows `@img/sharp-libvips*` as `LGPL-3.0-or-later`, but the repo states `Apache 2.0`.
The list is long, and I have carefully reviewed it, but if there are any issues, please contact me.