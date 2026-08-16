// fodpr_menu.m — Fodpr Chat macOS メニューバー設定
//
// SDL アプリは既定で最小限のメニューしか持たないため、標準的な
// アプリメニュー (終了/About)・編集メニュー・ウィンドウメニューを
// 追加する。SDL のウィンドウ生成後に呼ぶこと (SDL が NSApplication を
// 初期化した後である必要がある)。
//
// ビルド: clang -c -fobjc-arc -O2 fodpr_menu.m -o fodpr_menu.o

#import <AppKit/AppKit.h>

static NSMenuItem *fodprMenuItem(NSString *title, SEL action, NSString *key) {
  return [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:key];
}

void fodpr_install_menu(void) {
  @autoreleasepool {
    NSApplication *app = [NSApplication sharedApplication];

    NSMenu *mainMenu = [[NSMenu alloc] initWithTitle:@"MainMenu"];

    // --- アプリメニュー ---
    NSMenuItem *appItem = [[NSMenuItem alloc] initWithTitle:@"" action:NULL keyEquivalent:@""];
    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"Fodpr Chat"];
    [appMenu addItem:fodprMenuItem(@"Fodpr Chat について", @selector(orderFrontStandardAboutPanel:), @"")];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItem:fodprMenuItem(@"Fodpr Chat を終了", @selector(terminate:), @"q")];
    [appItem setSubmenu:appMenu];
    [mainMenu addItem:appItem];

    // --- 編集メニュー (ショートカット表示。実際のキー処理は SDL 側) ---
    NSMenuItem *editItem = [[NSMenuItem alloc] initWithTitle:@"編集" action:NULL keyEquivalent:@""];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"編集"];
    [editMenu addItem:fodprMenuItem(@"取り消し", @selector(undo:), @"z")];
    [editMenu addItem:fodprMenuItem(@"やり直し", @selector(redo:), @"Z")];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItem:fodprMenuItem(@"カット", @selector(cut:), @"x")];
    [editMenu addItem:fodprMenuItem(@"コピー", @selector(copy:), @"c")];
    [editMenu addItem:fodprMenuItem(@"ペースト", @selector(paste:), @"v")];
    [editMenu addItem:fodprMenuItem(@"すべてを選択", @selector(selectAll:), @"a")];
    [editItem setSubmenu:editMenu];
    [mainMenu addItem:editItem];

    // --- ウィンドウメニュー ---
    NSMenuItem *windowItem = [[NSMenuItem alloc] initWithTitle:@"ウィンドウ" action:NULL keyEquivalent:@""];
    NSMenu *windowMenu = [[NSMenu alloc] initWithTitle:@"ウィンドウ"];
    [windowMenu addItem:fodprMenuItem(@"最小化", @selector(performMiniaturize:), @"m")];
    [windowMenu addItem:fodprMenuItem(@"閉じる", @selector(performClose:), @"w")];
    [windowItem setSubmenu:windowMenu];
    [mainMenu addItem:windowItem];

    [app setMainMenu:mainMenu];
  }
}
