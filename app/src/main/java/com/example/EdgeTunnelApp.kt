package com.example

import android.app.Application
import com.example.data.ConfigRepository
import com.example.protocol.WorkerTester
import com.example.vpn.VpnStateRepository

class AppContainer(application: Application) {
  val configRepository = ConfigRepository(application)
  val vpnStateRepository = VpnStateRepository()
  val workerTester = WorkerTester(vpnStateRepository)
}

class EdgeTunnelApp : Application() {
  lateinit var container: AppContainer
    private set

  override fun onCreate() {
    super.onCreate()
    container = AppContainer(this)
  }
}
