## KernelProtection

> 测试环境：win10

### 效果

1.Protection1

方法1:通过官方提供注册回调 ObRegisterCallbacks 实现

![res/protection1](res/protection1.jpg)



2.Protection2

方法2:通过 hook nt!NtOpenProcess 实现

![](res/protection2.jpg)