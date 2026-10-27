## What and why

<!-- What does this change do, and which issue does it address? -->

## How it was tested

- [ ] `ctest --preset linux-debug` passes
- [ ] Sanitizer build (`linux-sanitize`) passes, for parser or analysis changes
- [ ] New or changed behavior has tests; fixed bugs have a regression test

## Safety checklist

- [ ] No analyzed file is executed, loaded or passed to a shell
- [ ] Every offset, size and count from the file is range-checked
- [ ] New loops over file data are bounded by a limit
- [ ] File-derived text is shown as plain text and escaped in reports
- [ ] Documentation is updated
