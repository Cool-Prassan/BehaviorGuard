'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('bgAPI', {
  // ── Queries ───────────────────────────────────────────────
  getStats:        ()  => ipcRenderer.invoke('get-stats'),
  getAlerts:       ()  => ipcRenderer.invoke('get-alerts'),
  getSettings:     ()  => ipcRenderer.invoke('get-settings'),
  getVersion:      ()  => ipcRenderer.invoke('get-version'),
  getPasswordData: ()  => ipcRenderer.invoke('get-password-data'),
  hasSetup:        ()  => ipcRenderer.invoke('has-setup'),

  // ── Commands ──────────────────────────────────────────────
  saveSettings:     (s)  => ipcRenderer.invoke('save-settings', s),
  clearAlerts:      ()   => ipcRenderer.invoke('clear-alerts'),
  resetProfile:     ()   => ipcRenderer.invoke('reset-profile'),
  exportProfile:    ()   => ipcRenderer.invoke('export-profile'),
  importProfile:    ()   => ipcRenderer.invoke('import-profile'),
  startMonitoring:  ()   => ipcRenderer.invoke('start-monitoring'),
  stopMonitoring:   ()   => ipcRenderer.invoke('stop-monitoring'),
  toggleMonitoring: ()   => ipcRenderer.invoke('toggle-monitoring'),
  unlock:           ()   => ipcRenderer.invoke('unlock'),

  // ── Password & Setup ──────────────────────────────────────
  savePassword:  (data) => ipcRenderer.invoke('save-password', data),
  checkPassword: (pw)   => ipcRenderer.invoke('check-password', pw),
  resetPassword: (pw)   => ipcRenderer.invoke('reset-password', pw),
  finishSetup:   ()     => ipcRenderer.invoke('finish-setup'),

  // ── Window chrome ─────────────────────────────────────────
  minimize: () => ipcRenderer.invoke('win-minimize'),
  maximize: () => ipcRenderer.invoke('win-maximize'),
  hide:     () => ipcRenderer.invoke('win-hide'),

  // ── Event bus (main → renderer) ───────────────────────────
  on(channel, cb) {
    const ALLOWED = [
      'stats-update','risk-update','alert','monitoring-status',
      'training-complete','training-phase','profile-loaded','profile-reset','navigate',
    ];
    if (!ALLOWED.includes(channel)) return;
    const wrapped = (_, ...args) => cb(...args);
    ipcRenderer.on(channel, wrapped);
    return () => ipcRenderer.removeListener(channel, wrapped);
  },
  off(channel, cb) {
    ipcRenderer.removeListener(channel, cb);
  },
});