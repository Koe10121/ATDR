<template>
  <div class="receive-form-page">
    <AppSectionHero
      title="แบบฟอร์มรับ / สืบมา"
      subtitle="หน้าจอ mockup สำหรับบันทึกข้อมูลเอกสาร, แนบไฟล์, และตรวจผลลัพธ์ OCR ก่อนบันทึกเข้าระบบ"
      :stats="heroStats"
      :show-refresh="false"
      :meta-label="'โหมดข้อมูล'"
      :meta-value="'Mock data'"
    />

    <CCard class="bg-style2 mb-4 page-card">
      <CCardBody>
        <div class="section-title">
          <CIcon name="cil-description" class="mr-2" />
          ข้อมูลเอกสาร
        </div>

        <CRow>
          <CCol md="4" sm="6">
            <CPInput v-model="form.documentNo" label="เลขที่เอกสาร" required />
          </CCol>
          <CCol md="4" sm="6">
            <CPDateInput v-model="form.receivedDate" label="วันที่รับเอกสาร" required />
          </CCol>
          <CCol md="4" sm="6">
            <CPSelect
              v-model="form.documentType"
              :options="documentTypeOptions"
              label="ประเภทเอกสาร"
              label-key="label"
              track-by="value"
              required
            />
          </CCol>
        </CRow>

        <CRow>
          <CCol md="4" sm="6">
            <CPInput v-model="form.senderName" label="หน่วยงาน/ผู้ส่ง" required />
          </CCol>
          <CCol md="4" sm="6">
            <CPSelect
              v-model="form.destination"
              :options="destinationOptions"
              label="หน่วยงานผู้รับผิดชอบ"
              label-key="label"
              track-by="value"
            />
          </CCol>
          <CCol md="4" sm="6">
            <CPSelect
              v-model="form.priority"
              :options="priorityOptions"
              label="ระดับความเร่งด่วน"
              label-key="label"
              track-by="value"
            />
          </CCol>
        </CRow>

        <CRow>
          <CCol md="4" sm="6">
            <CPInput v-model="form.contactName" label="ผู้ประสานงาน" />
          </CCol>
          <CCol md="4" sm="6">
            <CPInput v-model="form.contactPhone" label="เบอร์ติดต่อ" />
          </CCol>
          <CCol md="4" sm="6">
            <CPNumberInput v-model="form.expectedDocuments" label="จำนวนรายการคาดการณ์" :min="1" />
          </CCol>
        </CRow>

        <div class="textarea-block">
          <CPQuillEditor
            v-model="form.note"
            label="หมายเหตุ"
            :editor-class="'receive-form-editor'"
          />
        </div>
      </CCardBody>
    </CCard>

    <CCard class="bg-style2 mb-4 page-card">
      <CCardBody>
        <div class="upload-header">
          <div class="section-title mb-0">
            <CIcon name="cil-cloud-upload" class="mr-2" />
            อัปโหลดไฟล์
          </div>

          <div class="upload-actions">
            <CButton color="light" class="action-pill" @click="triggerFilePicker">
              <CIcon name="cil-folder-open" class="mr-2" />
              เลือกไฟล์
            </CButton>
            <CButton color="danger" variant="outline" class="action-pill" @click="clearUploads">
              <CIcon name="cil-trash" class="mr-2" />
              ล้างรายการ
            </CButton>
          </div>
        </div>

        <div class="upload-caption">อัปโหลดเอกสารไฟล์ PDF / JPG / JPEG / PNG เพื่อจำลองขั้นตอน OCR</div>

        <input
          ref="fileInput"
          type="file"
          class="d-none"
          multiple
          accept=".pdf,.jpg,.jpeg,.png"
          @change="handleFileChange"
        >

        <div class="upload-dropzone" @click="triggerFilePicker">
          <div class="upload-dropzone__icon">
            <CIcon name="cil-cloud-upload" />
          </div>
          <div class="upload-dropzone__title">เลือกไฟล์</div>
          <div class="upload-dropzone__hint">
            ประเภทที่รองรับ: PDF, JPG, JPEG, PNG
          </div>
          <div class="upload-dropzone__hint">ขนาดไฟล์ไม่เกิน 10MB</div>
        </div>

        <div v-if="uploadedFiles.length" class="file-grid">
          <div v-for="file in uploadedFiles" :key="file.id" class="file-chip">
            <div class="file-chip__meta">
              <div class="file-chip__name">{{ file.name }}</div>
              <div class="file-chip__detail">{{ file.typeLabel }} • {{ file.sizeLabel }}</div>
            </div>
            <CButton size="sm" color="danger" variant="ghost" @click="removeUpload(file.id)">
              <CIcon name="cil-trash" />
            </CButton>
          </div>
        </div>

        <div v-else class="upload-empty">
          <CIcon name="cil-folder-open" />
          <div>ยังไม่มีไฟล์ที่อัปโหลด</div>
        </div>
      </CCardBody>
    </CCard>

    <CCard class="bg-style2 mb-4 page-card">
      <CCardBody>
        <div class="ocr-header">
          <div class="section-title mb-0">
            <CIcon name="cil-layers" class="mr-2" />
            ผลลัพธ์ OCR
          </div>

          <CButton color="info" class="refresh-button" @click="refreshMockResults">
            <CIcon name="cil-reload" />
          </CButton>
        </div>

        <CDataTable
          hover
          striped
          :items="ocrResults"
          :fields="ocrFields"
          :items-per-page="8"
          pagination
        >
          <template #index="{ index }">
            <td class="text-center font-weight-bold">{{ index + 1 }}</td>
          </template>
          <template #statusLabel="{ item }">
            <td>
              <CBadge :color="statusColor(item.statusKey)">{{ item.statusLabel }}</CBadge>
            </td>
          </template>
          <template #confidenceLabel="{ item }">
            <td>
              <div class="confidence-cell">
                <span>{{ item.confidenceLabel }}</span>
                <CProgress
                  height="6px"
                  :value="item.confidence"
                  :color="item.confidence >= 90 ? 'success' : item.confidence >= 80 ? 'warning' : 'danger'"
                />
              </div>
            </td>
          </template>
          <template #actions="{ item }">
            <td class="text-center">
              <CButton
                size="sm"
                color="primary"
                class="table-action mr-2"
                @click="addSelectedItem(item)"
              >
                <CIcon name="cil-plus" />
              </CButton>
              <CButton
                size="sm"
                color="danger"
                class="table-action"
                @click="removeSelectedItem(item.id)"
              >
                <CIcon name="cil-trash" />
              </CButton>
            </td>
          </template>
        </CDataTable>
      </CCardBody>
    </CCard>

    <CRow>
      <CCol lg="8">
        <CCard class="bg-style2 page-card mb-4">
          <CCardBody>
            <div class="section-title">
              <CIcon name="cil-list-rich" class="mr-2" />
              รายการที่เตรียมบันทึก
            </div>

            <div v-if="selectedItems.length" class="selected-list">
              <div v-for="item in selectedItems" :key="item.id" class="selected-row">
                <div>
                  <div class="selected-row__title">{{ item.documentName }}</div>
                  <div class="selected-row__detail">
                    {{ item.categoryLabel }} • {{ item.referenceNo }} • ความมั่นใจ {{ item.confidenceLabel }}
                  </div>
                </div>
                <CButton size="sm" color="danger" variant="outline" shape="pill" @click="removeSelectedItem(item.id)">
                  ลบ
                </CButton>
              </div>
            </div>

            <div v-else class="selected-empty">
              ยังไม่มีรายการที่เลือกจากผล OCR
            </div>
          </CCardBody>
        </CCard>
      </CCol>

      <CCol lg="4">
        <CCard class="bg-style2 page-card mb-4">
          <CCardBody>
            <div class="section-title">
              <CIcon name="cil-speedometer" class="mr-2" />
              สรุปการบันทึก
            </div>

            <div class="summary-list">
              <div class="summary-row">
                <span>จำนวนไฟล์</span>
                <strong>{{ uploadedFiles.length }}</strong>
              </div>
              <div class="summary-row">
                <span>ผล OCR พร้อมใช้งาน</span>
                <strong>{{ readyCount }}</strong>
              </div>
              <div class="summary-row">
                <span>รายการที่เลือก</span>
                <strong>{{ selectedItems.length }}</strong>
              </div>
              <div class="summary-row">
                <span>เอกสารคาดการณ์</span>
                <strong>{{ form.expectedDocuments || '-' }}</strong>
              </div>
            </div>

            <div class="summary-actions">
              <CButton color="success" block class="mb-2" @click="saveMock">
                <CIcon name="cil-save" class="mr-2" />
                บันทึกข้อมูล
              </CButton>
              <CButton color="light" block @click="resetForm">
                <CIcon name="cil-reload" class="mr-2" />
                เริ่มใหม่
              </CButton>
            </div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  </div>
</template>

<script>
import AppSectionHero from '@/projects/components/layout/AppSectionHero'
import CPInput from '@/projects/components/custom/CPInput'
import CPSelect from '@/projects/components/custom/CPSelect'
import CPDateInput from '@/projects/components/custom/CPDateInput'
import CPNumberInput from '@/projects/components/custom/CPNumberInput'
import CPQuillEditor from '@/projects/components/custom/CPQuillEditor'
import { notifyInfo, notifySuccess, notifyWarning } from '@/projects/utils/notify'

function createFormState() {
  return {
    documentNo: 'REC-2026-0038',
    receivedDate: '2026-03-10',
    documentType: { value: 'incoming', label: 'หนังสือรับเข้า' },
    senderName: 'สำนักวิชาวิทยาศาสตร์สุขภาพ',
    destination: { value: 'saraban', label: 'งานสารบรรณกลาง' },
    priority: { value: 'normal', label: 'ปกติ' },
    contactName: 'กัญญารัตน์ ศรีคำ',
    contactPhone: '053-917-000',
    expectedDocuments: 5,
    note: 'ข้อมูลชุดนี้เป็น mockup สำหรับทดสอบหน้าจอบันทึกเอกสารและตรวจผล OCR'
  }
}

function createOcrResults() {
  return [
    {
      id: 'ocr-001',
      documentName: 'การดำเนินกิจกรรมอบรมและถ่ายทอดสารสนเทศเพื่อพัฒนาการศึกษา ครั้งที่ 46',
      referenceNo: 'DOC-2026-0001',
      categoryLabel: 'หนังสือภายนอก',
      confidence: 96,
      statusKey: 'ready'
    },
    {
      id: 'ocr-002',
      documentName: 'โครงการสัมมนา การดำเนินกิจกรรมอบรมและถ่ายทอดสารสนเทศเพื่อพัฒนาการศึกษา',
      referenceNo: 'DOC-2026-0002',
      categoryLabel: 'รายงานโครงการ',
      confidence: 89,
      statusKey: 'review'
    },
    {
      id: 'ocr-003',
      documentName: 'โครงการสัมมนา การดำเนินกิจกรรมอบรมและถ่ายทอดสารสนเทศเพื่อพัฒนาการศึกษา ครั้งที่ 45',
      referenceNo: 'DOC-2026-0003',
      categoryLabel: 'รายงานโครงการ',
      confidence: 93,
      statusKey: 'ready'
    },
    {
      id: 'ocr-004',
      documentName: 'การดำเนินกิจกรรมอบรมและถ่ายทอดสารสนเทศเพื่อพัฒนาการศึกษา',
      referenceNo: 'DOC-2026-0004',
      categoryLabel: 'บันทึกข้อความ',
      confidence: 91,
      statusKey: 'ready'
    },
    {
      id: 'ocr-005',
      documentName: 'ขอประชาสัมพันธ์และเชิญชวนร่วมงาน การดำเนินกิจกรรมอบรมและถ่ายทอดสารสนเทศ ครั้งที่ 50',
      referenceNo: 'DOC-2026-0005',
      categoryLabel: 'หนังสือประชาสัมพันธ์',
      confidence: 84,
      statusKey: 'review'
    }
  ].map(item => ({
    ...item,
    confidenceLabel: `${item.confidence}%`,
    statusLabel: item.statusKey === 'ready' ? 'พร้อมบันทึก' : 'ตรวจสอบ'
  }))
}

export default {
  name: 'ReceiveForm',
  components: {
    AppSectionHero,
    CPInput,
    CPSelect,
    CPDateInput,
    CPNumberInput,
    CPQuillEditor
  },
  data() {
    return {
      form: createFormState(),
      uploadedFiles: [],
      ocrResults: createOcrResults(),
      selectedItems: [],
      documentTypeOptions: [
        { value: 'incoming', label: 'หนังสือรับเข้า' },
        { value: 'memo', label: 'บันทึกข้อความ' },
        { value: 'project', label: 'เอกสารโครงการ' }
      ],
      destinationOptions: [
        { value: 'saraban', label: 'งานสารบรรณกลาง' },
        { value: 'secretary', label: 'สำนักงานเลขานุการ' },
        { value: 'academic', label: 'ฝ่ายวิชาการ' }
      ],
      priorityOptions: [
        { value: 'normal', label: 'ปกติ' },
        { value: 'urgent', label: 'ด่วน' },
        { value: 'very-urgent', label: 'ด่วนมาก' }
      ],
      ocrFields: [
        { key: 'index', label: '#', _style: 'width: 60px; text-align:center;' },
        { key: 'documentName', label: 'ชื่อเอกสาร' },
        { key: 'referenceNo', label: 'เลขอ้างอิง', _style: 'width: 150px;' },
        { key: 'categoryLabel', label: 'ประเภท', _style: 'width: 160px;' },
        { key: 'confidenceLabel', label: 'ความมั่นใจ', _style: 'width: 180px;' },
        { key: 'statusLabel', label: 'สถานะ', _style: 'width: 130px;' },
        { key: 'actions', label: 'การดำเนินการ', _style: 'width: 140px; text-align:center;' }
      ]
    }
  },
  computed: {
    readyCount() {
      return this.ocrResults.filter(item => item.statusKey === 'ready').length
    },
    heroStats() {
      return [
        { label: 'Uploaded Files', value: this.uploadedFiles.length, hint: 'จำนวนไฟล์ที่แนบใน mock session', icon: 'cil-cloud-upload', iconClass: 'app-section-stat__icon--total' },
        { label: 'OCR Ready', value: this.readyCount, hint: 'รายการที่พร้อมบันทึกโดยไม่ต้องแก้เพิ่ม', icon: 'cil-check-circle', iconClass: 'app-section-stat__icon--active' },
        { label: 'Selected Items', value: this.selectedItems.length, hint: 'รายการที่ถูกเลือกเพื่อบันทึกเข้าระบบ', icon: 'cil-list-rich', iconClass: 'app-section-stat__icon--attention' }
      ]
    }
  },
  methods: {
    statusColor(statusKey) {
      return statusKey === 'ready' ? 'success' : 'warning'
    },
    triggerFilePicker() {
      this.$refs.fileInput.click()
    },
    handleFileChange(event) {
      const files = Array.from((event && event.target && event.target.files) || [])
      if (!files.length) return

      const nextItems = files.map((file, index) => ({
        id: `${file.name}-${file.size}-${index}-${Date.now()}`,
        name: file.name,
        sizeLabel: this.formatBytes(file.size),
        typeLabel: file.type || 'unknown'
      }))

      this.uploadedFiles = [...this.uploadedFiles, ...nextItems]
      event.target.value = ''
      notifyInfo(this.$store, `เพิ่มไฟล์จำลองแล้ว ${nextItems.length} รายการ`)
    },
    removeUpload(id) {
      this.uploadedFiles = this.uploadedFiles.filter(item => item.id !== id)
    },
    clearUploads() {
      this.uploadedFiles = []
      notifyWarning(this.$store, 'ล้างรายการไฟล์ที่อัปโหลดแล้ว')
    },
    refreshMockResults() {
      this.ocrResults = this.ocrResults.map(item => {
        const shift = Math.floor(Math.random() * 7) - 3
        const confidence = Math.min(99, Math.max(78, item.confidence + shift))
        const statusKey = confidence >= 90 ? 'ready' : 'review'
        return {
          ...item,
          confidence,
          confidenceLabel: `${confidence}%`,
          statusKey,
          statusLabel: statusKey === 'ready' ? 'พร้อมบันทึก' : 'ตรวจสอบ'
        }
      })
    },
    addSelectedItem(item) {
      if (this.selectedItems.some(selected => selected.id === item.id)) {
        notifyInfo(this.$store, 'รายการนี้ถูกเลือกไว้แล้ว')
        return
      }
      this.selectedItems = [...this.selectedItems, { ...item }]
    },
    removeSelectedItem(id) {
      this.selectedItems = this.selectedItems.filter(item => item.id !== id)
    },
    saveMock() {
      if (!this.form.documentNo || !this.form.receivedDate || !this.form.senderName) {
        notifyWarning(this.$store, 'กรุณากรอกข้อมูลเอกสารให้ครบก่อนบันทึก')
        return
      }

      if (!this.selectedItems.length) {
        notifyWarning(this.$store, 'กรุณาเลือกรายการจากผล OCR อย่างน้อย 1 รายการ')
        return
      }

      notifySuccess(this.$store, `บันทึกข้อมูล mock สำเร็จ ${this.selectedItems.length} รายการ`)
    },
    resetForm() {
      this.form = createFormState()
      this.uploadedFiles = []
      this.ocrResults = createOcrResults()
      this.selectedItems = []
    },
    formatBytes(bytes) {
      if (!bytes) return '0 B'
      const units = ['B', 'KB', 'MB', 'GB']
      const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
      const value = bytes / (1024 ** exponent)
      return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`
    }
  }
}
</script>

<style scoped lang="scss">
@import "./receive-form.shared.scss";
</style>
