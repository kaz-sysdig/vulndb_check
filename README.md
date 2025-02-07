```
% python3 vulndb_check.py
=== Aggregated Results ===
Total vulnerabilities detected: 10769
Total vulnerabilities from 'vulndb': 3870
'vulndb' Percentage: 35.94%
```
```
% python3 vulndb_check_legacy.py
Fetching scanning results...
Successfully fetched scanning results.
Found 14 images to analyze.
Processing 1/14: 175ffd71cce3d90bae95904b55260db941b10007a4e5471a19f3135b30aa9cd1
Processing 2/14: fccf770c138c10f5bebc172ed763408bf79152446552c92b1f9bc8ff3fba3269
Processing 3/14: 1c32c8ab07fbd84d5880ddd98e388b0a2d58dbde9b138c9b470ef602524dc0a6
Processing 4/14: 470b7b878af639d6f1c8125f9b3f8f13c4c1d126ff9e8e1498f21f663184bbac
Processing 5/14: 79dcf4f41ae9212f4e5649f3bdb5e4c769796322a8b45c2dfbd63e63a3a5bf8d
Processing 6/14: e6ea68648f0cd70c8d77c79e8cd4c17f63d587815afcf274909b591cb0e417ab
Processing 7/14: 60c005f310ff3ad6d131805170f07d2946095307063eaaa5eedcaf06a0a89561
Processing 8/14: f9c3c1813269cff6c2290c404f0997b5a597e366cc0a6e42d076dec32776c461
Processing 9/14: c69fa2e9cbf5f42dc48af631e956d3f95724c13f91596bc567591790e5e36db6
Processing 10/14: 75392e3500e3675026eb95f4b400e9af90a9a48616ec6b5ed93883a9fb60f7dc
Processing 11/14: 2e96e5913fc06e3d26915af3d0f2ca5048cc4b6327e661e80da792cbf8d8d9d4
Processing 12/14: 9611051aba027ab8a484faedca8207e743193565559dffef2a90d9d62c41e647
Processing 13/14: 9aa1fad941575eed91ab13d44f3e4cb5b1ff4e09cbbe954ea63002289416a13b
Processing 14/14: 6bab7719df1001fdcc7e39f1decfa1f73b7f3af2757a91c5bafa1aaea29d1aee
Finished processing all images.
Total number of vulnerabilities: 233
Occurrences per feed_group: Counter({'rhel:8': 193, 'alpine:3.13': 29, 'nvdv2:cves': 7, 'vulndb:vulnerabilities': 3, 'debian:12': 1})
Percentage of 'vulndb:vulnerabilities' among all vulnerabilities: 1.29%
```

