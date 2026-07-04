package pro.curator.antibot.demo

import android.app.Application

/**
 * Host application.
 *
 * In a real app you would call `AntiBot.init(this, config)` here in onCreate,
 * with the server public key PINNED into the app (BuildConfig/asset). This demo
 * instead initializes on demand from the UI and fetches the key from the local
 * test server so you can point it at any running instance without rebuilding —
 * see [DemoViewModel]. The pattern is called out in the on-screen notes.
 */
class DemoApp : Application()
