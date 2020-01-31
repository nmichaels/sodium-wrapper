const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("sodium", "src/nacl.zig");
    lib.setBuildMode(mode);
    lib.install();


    var tests = b.addTest("src/nacl.zig");
    tests.setBuildMode(mode);
    tests.linkSystemLibrary("c");
    tests.linkSystemLibrary("sodium");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}
