---
title: FlowDroid
platform: android
source: https://github.com/secure-software-engineering/FlowDroid
---

[FlowDroid](https://github.com/secure-software-engineering/FlowDroid) is an open-source tool based in [soot](https://github.com/soot-oss/soot "soot"), a framework dedicated to analyzing and translating Java bytecode for easier analysis. The tool handles the nuances of Android app lifecycles (like `onCreate`, `onStart`, `onPause`, and others) and its UI components during analysis and performs taint analysis that is:

- **Context-sensitive**: Distinguishing between calls to the same method based on their specific execution contexts.
- **Object-sensitive**: Identifying individual objects, even when they're of the same class.
- **Flow-sensitive**: Recognizing the sequential order of code execution.

FlowDroid can be used in two ways: as a standalone command line tool for quick analyses or as a library for more complex investigations. In addition to performing taint analysis, FlowDroid can also generate call graphs, as illustrated in [this blog post](https://medium.com/geekculture/generating-call-graphs-in-android-using-flowdroid-pointsto-analysis-7b2e296e6697 "Generating Call Graphs in Android Using FlowDroid + PointsTo Analysis by Navid Salehnamadi").
