; ModuleID = 'sizeof'
source_filename = "sizeof"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "aarch64-apple-darwin"

define i64 @bytes_of_three() {
entry:
  %7 = mul i64 ptrtoint (ptr getelementptr (i64, ptr null, i32 1) to i64), 3
  ret i64 %7
}
