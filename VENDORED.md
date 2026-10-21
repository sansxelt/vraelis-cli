# Vendored modules

The two subpackages were developed as separate tools (`modellock`, `addonlock`) in a private repository and are vendored here. Source commits are listed so the record is fixed; the source repository itself is not public.

`vraelis/models/` is Model Lock at 8c4dec3bcf8a657b4989f81b7dd8fabb0e84a450, package `modellock/`.
`vraelis/agents/` is Add-on Lock at 02b0edfad17d2e0c29dc1c69b4fe060c00710460, package `addonlock/`.
Each package's `__main__.py` is not vendored (the top-level `vraelis/__main__.py` replaces both).
The only change to vendored code is the argparse `prog` string in each `cli.py` ("modellock" -> "vraelis models",
"addonlock" -> "vraelis agents"). Lockfile file names (modellock.json, addonlock.json) are unchanged.

| vendored file | source file | source sha256 | vendored sha256 | identical |
|---|---|---|---|---|
| vraelis/models/__init__.py | modellock/__init__.py | ed5485346d1ffc7a1d6b8f4725a314d52a56537226672f1b0285c0d22ea083f7 | ed5485346d1ffc7a1d6b8f4725a314d52a56537226672f1b0285c0d22ea083f7 | yes |
| vraelis/models/cli.py | modellock/cli.py | 8e1f9b3e59603484bcea2053e7aaf4d21b3aa0bca56889dfa8ce9e4420709f5e | e0a4e76f1ff389c8e585daac2b6f57dc002117d48258257572a88dae3c2c331d | no (prog string) |
| vraelis/models/core.py | modellock/core.py | 983ab8f55ef1af0e1f537e4ce87d6ac9ff766a86c170771744ad0910269afff4 | 983ab8f55ef1af0e1f537e4ce87d6ac9ff766a86c170771744ad0910269afff4 | yes |
| vraelis/models/modelcheck.py | modellock/modelcheck.py | 97d16953760426bd9d38400e2eb077f3dd1dab5e447fc86b1b0baf62159d4351 | 97d16953760426bd9d38400e2eb077f3dd1dab5e447fc86b1b0baf62159d4351 | yes |
| vraelis/models/serialization_1_1.py | modellock/serialization_1_1.py | 834103f7bc9e3627b18b1b6197016afbebb0520cf17dd783ebf58fa7c6fc49a1 | 834103f7bc9e3627b18b1b6197016afbebb0520cf17dd783ebf58fa7c6fc49a1 | yes |
| vraelis/models/signature.py | modellock/signature.py | eec6ee0399fbf334d91b8622163af9b6ed8ad4c2ffaf53b716ddb8a16208b478 | eec6ee0399fbf334d91b8622163af9b6ed8ad4c2ffaf53b716ddb8a16208b478 | yes |
| vraelis/agents/__init__.py | addonlock/__init__.py | 520b32fd9810cfb67d394c4037c05dd9101bb5f805807b9cef5d3d8139068463 | 520b32fd9810cfb67d394c4037c05dd9101bb5f805807b9cef5d3d8139068463 | yes |
| vraelis/agents/cli.py | addonlock/cli.py | e9cf9c22829e89671ae88d4dcdf1bf162ae93a90a279a646fb1ba685d6273d65 | 2844f0fb47332fd83b8bf95afba8fa9a5f3e4256a88c0cb512ae4556e51b4c28 | no (prog string) |
| vraelis/agents/core.py | addonlock/core.py | a50d03523fadd83f884d6822ae1490cdef9019e7b6f9b7ab6affd2f391eb04bf | a50d03523fadd83f884d6822ae1490cdef9019e7b6f9b7ab6affd2f391eb04bf | yes |
| vraelis/agents/ignore.py | addonlock/ignore.py | 563fb096b155f8d673e22c92f0c40d4c2a37b07e4f9c29329830acff4a6638aa | 563fb096b155f8d673e22c92f0c40d4c2a37b07e4f9c29329830acff4a6638aa | yes |
| vraelis/agents/paths.py | addonlock/paths.py | cab1a0eb31ff3ecc9962ac85a767fce35bf91a8b17cfea90b45f9c2b79015bbf | cab1a0eb31ff3ecc9962ac85a767fce35bf91a8b17cfea90b45f9c2b79015bbf | yes |
| vraelis/agents/redact.py | addonlock/redact.py | 0f5d4377d80010531292aa621aded5de89ad1e9b9113b46ebb92fe84f623e460 | 0f5d4377d80010531292aa621aded5de89ad1e9b9113b46ebb92fe84f623e460 | yes |
