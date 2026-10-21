
const got = require('got')
const Signer =  require('./signer')
const _ = require('lodash')
const sortAndStringify = require('./util')

class SSQSign {
  /**
   * @param {String} url
   * @param {String} developerId
   * @param {String} privateKey base64 string
   * @param {String} publicKey  base string
   * @param {Object} options  {alg,timeout,notifyUrl,returnUrl}
  */
  constructor(url, developerId, privateKey, publicKey, options = {}) {
    this.serverHost = url
    this.developerId = developerId
    this.account = options.account
    this.privateKey = privateKey
    this.publicKey = publicKey
    this.timeout = options.timeout || 20000
    this.retry = options.retry || 2
    this.pushUrl = options.pushUrl,
    this.returnUrl = options.returnUrl,
    this.alg = options.alg || 'SHA1withRSA'
    this.accessKey = options.accessKey || ''
    this.signer = new Signer(privateKey, publicKey)

  }
  /**
   * @param {String} url
   * @param {Object} query
   * @param {Object} body
   * @returns {String}
  */
  getSignPlainText(url, query, body) {
    let queryStr = sortAndStringify(query)
    let bodyMd5Val = ''
    if(!_.isEmpty(body)) {
      bodyMd5Val = this.signer.signWithMd5(JSON.stringify(body))
    }
    let urlInst = new URL(url)
    let urlPath = urlInst.pathname
    return `${queryStr}${urlPath}${bodyMd5Val}`
  }

  /**
   * @param {String} url
   * @param {Object} query
   * @param {Object} body
   * @returns {String}
  */
  sign(url, query, body) {
    let plainText = this.getSignPlainText(url, query, body)
    return this.signer.sign(plainText)
  }

  /**
   * @param {String} method
   * @param {String} url
   * @param {Object} data {query:object, form: object}
   * @param {Object} options {retry, timeout}
   * @returns {String}
  */
  async doRequest(method, url, data, options = {}) {
    let query = _.merge(this.createQueryParams(), data.query)
    let signVal = this.sign(url, query, data.form)
    let urlParamStr = Object.keys(query).map((key) => {
      return  `${key}=${query[key]}`
    }).join('&')
    url += `?${urlParamStr}&sign=${encodeURIComponent(signVal)}` 
    let response
    try {
      response = await got({
        method: method,
        url: url,
        json: data.form,
        retry: options.retry || this.retry,
        timeout: options.timeout || this.timeout,
        responseType: options.responseType || 'json',
      })
    }
    catch(e) {
      return {
        errno: 100002,
        data: {},
        errmsg: e.toString()
      }
    }
    
    return response.body
  }

  /**
   * @returns {Object} {developerId, rtick, signType}
  */
  createQueryParams() {
    return {developerId: this.developerId, rtick: Date.now(), signType: 'rsa'}
  }

  /**
   * @param {String} name idCard name
   * @param {String} identity idCard name code
   * @returns {Object}
  */
  async a2e(name, identity) {
    let routePath = '/credentialVerify/personal/identity2/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        name: name,
        identity: identity
      }
    })
    
    return responseBody
  }

  /**
   * @param {String} account 账号id
   * @param {String} name 身份证姓名
   * @param {String} identity 身份证编号
   * @param {String} mobile 用户手机号码
   * @returns {Object} {errno, errmsg, data}
  */
  async personReg(account, name, identity, mobile) {
    let routePath = '/user/reg/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        name: name,
        mobile: mobile,
        userType: '1',
        applyCert: '1',
        credential : {
          identity: identity
        }
      }
    })
    return responseBody
  }

  /**
   * 增加是否异步申请证书的选项配置
   * @param {String} account ssq user id
   * @param {Object} userInfo {name, identity, mobile?}
   * @param {Object} options {applyCert} 
   * @returns {Object} {errno, errmsg, data: {url}}
  */
  async personRegNV(account, userInfo, options = {}) {
    let routePath = '/user/reg/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        name: userInfo.name,
        mobile: userInfo.mobile,
        userType: '1',
        applyCert: options.applyCert || '0',
        credential : {
          identity: userInfo.identity
        }
      }
    })
    return responseBody
  }

  /**
   * 合同新版申请证书
   * @param {String} account ssq user id
   * @param {Object} userInfo {name, identity, mobile?}
   * @param {Object} options {applyCert} 
   * @param {String} agreementId 认证协议阅读同意的业务编号
   * @param {String} flowId 身份校验通过的业务编号
   * @param {String} orderNo 意愿性校验通过的业务编号
   * @returns {Object} {errno, errmsg, data: {url}}
  */
  async personRegNew(account, userInfo, agreementId, flowId, orderNo, options = {}) {
    let routePath = '/user/reg/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        name: userInfo.name,
        mobile: userInfo.mobile,
        userType: '1',
        applyCert: options.applyCert || '0',
        credential : {
          identity: userInfo.identity
        },
        agreementId: agreementId,
        flowId: flowId,
        orderNo: orderNo
      }
    })
    return responseBody
  }

  /**
   * 查询证书编号
   * @param {String} account ssq user id
  */
  async userGetCert(account) {
    let routePath = '/user/getCert/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account
        }
      }
    )
    return responseBody
  }

  /**
   * 查询用户有效证书信息
   * @param {String} account ssq user id
  */
  async userGetValidCertsByAccount(account) {
    let routePath = '/user/getValidCertsByAccount/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account
        }
      }
    )
    return responseBody
  }

  /**
   * @param {String} account 为目标账号申请签名或创建默认签名
   * @returns {Object} {errno,errmsg,data: {}}
  */
  async createUserDefaultSignImage(account) {
    let routePath = '/signatureImage/user/create/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account
      }
    })
    return responseBody

  }

  /**
   * @param {String} account 查询用户的id
   * @param {String} taskId personReg 接口产生出的taskId
   * @returns {Object} {errno, errmsg, data: {message, status}} data.status == '5' is ok
  */
  async syncApplyCertStatus(account,  taskId) {
    let routePath = '/user/async/applyCert/status/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        taskId: taskId 
      }
    })
    return responseBody
  }

  /**
   * @param {String} filename 
   * @param {Buffer} fileData
   * @param {Number} totalPage 文件
   * @return {boject} {errno, data: {fid}, errmsg}
  */
  async uploadPdf(filename, fileData, totalPage) {
    let routePath = '/storage/upload/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: this.account,
        fmd5: this.signer.signWithMd5(fileData),
        fname: filename,
        fdata: Buffer.from(fileData).toString('base64'),
        fpages: totalPage
      }
    })
    return responseBody
  }

 

  /**
   * @param {String} templateName 模板名称
   * @param {Object} pdfInfo {name, data, totalPage}
   * @param {Object} options {isReadForm}
   * @returns {Object} {errno, errmsg, data: {tid}}
  */
  async uploadTemplate(templateName, pdfInfo, options = {}) {
    let routePath = '/dist/template/upload/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: this.account,
        isReadForm: options.isReadForm || '0',
        fmd5: this.signer.signWithMd5(pdfInfo.data),
        fname: pdfInfo.name,
        ftype: 'pdf',
        title: templateName,
        fdata: Buffer.from(pdfInfo.data).toString('base64'),
        fpages: pdfInfo.totalPage
      }
    })
    return responseBody
  }


  /**
   * @param {Object} pdfInfo  {data, totalPage, name}
   * @param {Object} contractInfo {title, description}
   * @param {Object} options {expireTime}
   * @returns {Object} {errno, errmsg, data: {tid}}
  */
  async createContractByUploadPdf(pdfInfo, contractInfo, options = {}) {
    let routePath = '/storage/contract/upload/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: this.account,
        fmd5: this.signer.signWithMd5(pdfInfo.data),
        fname: pdfInfo.name,
        ftype: 'pdf',
        title: contractInfo.title,
        description: contractInfo.description || '',
        fdata: Buffer.from(pdfInfo.data).toString('base64'),
        fpages: pdfInfo.totalPage,
        expireTime: options.expireTime || (Math.floor(Date.now()/1000) + 7200).toString(),
      }
    })
    return responseBody
  }

  /**
   * 手动签
   * @param {String} signer 签署者
   * @param {String} contractId
   * @param {String} sid 业务侧id, 签署完成回传
   * @param {Object} options {expireTime(s), hwr, isShowHandwrittenTime, isDrawSignatureImage, returnUrl, pushUrl}
   * @returns {Object} {errno, errmsg, data: {url}}
   * 
  */
  async getUserSignContractUrl(signer, contractId, sid, options = {}) {
    let routePath = '/contract/send/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        signer: signer,
        contractId: contractId,
        expireTime: options.expireTime || (Math.floor(Date.now()/1000) + 1800).toString(),
        dpi: options.dpi || '160',
        isAllowChangeSignaturePosition: '1',
        sid: sid,
        hwr: options.hwr || '1',
        isShowHandwrittenTime: options.isShowHandwrittenTime || '1',
        signatureImageName: 'default',
        isDrawSignatureImage: options.isDrawSignatureImage || '2',
        returnUrl: options.returnUrl || this.returnUrl,
        pushUrl:  options.pushUrl || this.pushUrl,
        signaturePositions: [{
          dateTimeFormat: 'yyyy-MM-dd',
          pageNum: '1',
          x: '0.1',
          y: '0.1'
        }]
      }
    })
    return responseBody
  }

  /**
   * 搜索关键字完成签署, options.align 印章位于搜索到的关键字的相对位置
   * @param {String} contractId
   * @param {String} keyword
   * @param {Object} options {align}
  */
  async searchKeyWordSign(contractId, keyword, options = {}) {
    let routePath = '/contract/sign/keywords/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        contractId: contractId,
        signerAccount: this.account,
        keywords: [keyword],
        align: options.align || 'rc'
      }
    })
    return responseBody
  }

  async signContract(contractId, signaturePos, options) {
    let routePath = '/contract/sign/cert/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        contractId: contractId,
        signerAccount: this.account,
        signaturePositions: [{
          pageNum
        }]
      }
    })
    return responseBody
  }

  /**
   * 使用模板创建合同
   * @param {String} tid
   * @param {Object} params {key: value}
   * @param {Object} contractInfo {title: description}
   * @param {object} options {expireTime}
  */
  async createContractByTemplateId(tid, params = {}, contractInfo, options = {}) {
    let routePath = '/dist/template/createContract/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: this.account,
        tid: tid,
        title: contractInfo.title || '商品购买合同',
        templateValues: params,
        description: contractInfo.description || '',
        expireTime: options.expireTime || (Math.floor(Date.now()/1000) + 3600 *24 ).toString()
      }
    })
    return responseBody
  }

  /**
   * 服务方签署合同调用
   * @param {String} tid
   * @param {String} contractId
   * @param {Object} params 签署变量{varname: {}}
   * @param {Object} options {signWidth, signHeight}
   * @returns {Object} {errno, errmsg, data}
  */
  async signTemplateContract(tid, contractId, params = {},  options = {}) {
    let routePath = '/contract/sign/template/'
    Object.keys(params).forEach((item) => {
      params[item].account = this.account
    })
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        contractId: contractId,
        signerAccount: this.account,
        signatureImageWidth: options.signWidth,
        signatureImageHeight: options.signHeight,
        tid: tid,
        vars: params
      }
    })
    return responseBody
  }
  
  /**
   * 利用模板生成合同的手动签链接生成接口
   * @param {String} signer 签署者
   * @param {String} tid contract template id
   * @param {String} contractId
   * @param {String} sid  业务侧 id, 签完回传字段
   * @param {String} varnames 需要签署的字段
   * @returns {Object} {errno, errmsg, data}
   * 
  */
  async getUserSignTemplateContractUrl(signer, tid, contractId, sid, varnames,  options = {}) {
    let routePath = '/contract/sendByTemplate/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        contractId: contractId,
        sid: sid,
        dpi: options.dpi || '160',
        isVerifyAndSignCombine: options.isVerifyAndSignCombine || '0',
        faceFirst: '0',
        faceMethod: '0',
        hwr: options.hwr || '1',
        signatureImageHeight: options.signHeight,
        signer: signer,
        signatureImageWidth: options.signWidth,
        tid: tid,
        isDrawSignatureImage: options.isDrawSignatureImage,
        isShowHandwrittenTime: '1',
        isAllowChangeSignaturePosition: '1',
        varNames: varnames,
        vcodeMobile: options.vcodeMobile,
        returnUrl: options.returnUrl || this.returnUrl,
        pushUrl:  options.pushUrl || this.pushUrl,
        expireTime: options.expireTime || (Math.floor(Date.now()/1000) + 1800).toString(),
      }
    })
    return responseBody
  }

  /**
   * 锁定并结束合同，同事生成平台方提供的签署凭证
   * @param {String} contractId 合同id
   * @returns {Object} {errno, errmsg, data}
  */
  async lockContract(contractId) {
    let routePath = '/storage/contract/lock/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        contractId: contractId,
        signerAccount: this.account
      }
    })
    return responseBody
  }

  /**
   * 获取平台方的签署凭证文件
   * @param {String} contractId
   * @returns {Buffer}
  */
  async getContractSignProof(contractId) {
    let routePath = '/contract/downloadAttachment/'
    let responseBody = await this.doRequest('GET', `${this.serverHost}${routePath}`, {
      query: {
        contractId: contractId
      }
    }, {responseType: 'buffer'})
    return responseBody
  }

  /**
   * 获取模板中的变量， options.isRetrieveAllVars 取 '0' 或 '1'
   * @param {String} tid template contract id
   * @param {String} options {isRetrieveAllVars}
   * @returns {Object} {errno, errmsg, data}
  */
  async getTemplateVars(tid, options) {
    let routePath = '/template/getTemplateVars/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        tid: tid,
        isRetrieveAllVars: options.isRetrieveAllVars
      }
    })
    return responseBody
  }

  /**
   * @param {String} contractId
   * @param {Object} options {dpi, expireTime}
   * @returns {Object} {errno, errmsg, data: {url}}
  */
  async getContractPreviewUrl(contractId, options = {}) {
    let routePath = '/contract/getPreviewURL/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        contractId: contractId,
        account: this.account,
        dpi: options.dpi || '160',
        expireTime: options.expireTime || (Math.floor(Date.now()/1000) + 7200).toString(),
      }
    })
    return responseBody
  }

  /**
   * @param {String} contractId
   * @returns {Buffer}
  */
  async downloadContract(contractId) {
    let routePath = '/storage/contract/download/'
    let responseBody = await this.doRequest('GET', `${this.serverHost}${routePath}`, {
      query: {
        contractId: contractId
      }
    }, {responseType: 'buffer'})
    return responseBody
  }


  /**
   * 重新申请数字证书
   * @param account 用户id
   * @return {errno, errmsg, data}
  */
  async applyCert(account) {
    let routePath = '/user/reapplyCert/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account
      }
    })
    return responseBody
  }

  /**
   * 获取合同签署人状态
   * @param {String} contractId
   * @returns {Object} {errno, errmsg, data}
  */
  async getContractSignStatus(contractId) {
    let routePath = '/contract/getSignerStatus/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        contractId: contractId
      }
    })
    return responseBody
  }

  /**
   * 合同关键字查找位置
   * @param {String} contractId
   * @param {String} keyword
   * @returns {Object} {errno, errmsg, data}
  */
  async distContractFindKeywordPositions(contractId, keyword) {
    let routePath = '/dist/contract/findKeywordPositions/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        contractId: contractId,
        keyword: keyword
      }
    })
    return responseBody
  }

  /**
   * 查询个人用户证件信息
   * @param {String} account
   * @returns {Object} {errno, errmsg, data}
  */
  async userGetPersonalCredential(account) {
    let routePath = '/user/getPersonalCredential/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account
      }
    })
    return responseBody
  }

  /**
   * 手动签 v2
   * @param {String} signer 签署者
   * @param {String} contractId
   * @param {String} sid 业务侧id, 签署完成回传
   * @param {Object} options {expireTime(s), hwr, isShowHandwrittenTime, isDrawSignatureImage, returnUrl, pushUrl}
   * @returns {Object} {errno, errmsg, data: {url}}
   * 
  */
  async userSendContract(signer, contractId, sid, options = {}) {
    let routePath = '/contract/send/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        signer: signer,
        contractId: contractId,
        expireTime: options.expireTime || (Math.floor(Date.now()/1000) + 1800).toString(),
        dpi: options.dpi || '160',
        isAllowChangeSignaturePosition: '1',
        sid: sid,
        hwr: options.hwr || '1',
        isShowHandwrittenTime: options.isShowHandwrittenTime || '1',
        signatureImageName: 'default',
        isDrawSignatureImage: options.isDrawSignatureImage || '2',
        returnUrl: options.returnUrl || this.returnUrl,
        pushUrl:  options.pushUrl || this.pushUrl,
        signaturePositions: [{
          pageNum: options.pageNum || '1',
          x: options.x || '0.1',
          y: options.y || '0.1'
        }]
      }
    })
    return responseBody
  }

  /**
   * 验证通知的数据签名
   * @param {String} data rawBody
   * @param {String} rtick 时间戳
   * @param {String} signature
   * @returns {Boolean}
  */
  verifyNotifyData(data, rtick, signature) {
    let bodyMd5Val = this.signer.signWithMd5(data)
    let plainText = `${bodyMd5Val}${rtick}${this.accessKey}`
    let md5Val = this.signer.signWithMd5(plainText)
    return md5Val === signature.toString()
  }

  /**
   * 查询CA机构及其电子认证服务协议
   * @param {String} account
   * @param {String} userType 用户类型：“1”代表个人，“2”代表企业
   * @param {Object} options
   * @returns {Object} {errno, errmsg, data}
  */
  async userGetPersonalCredential(account, userType, options = {}) {
    let routePath = '/user/getPersonalCredential/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        userType: userType,
        returnUrl: options.returnUrl || this.returnUrl,
        pushUrl: options.pushUrl || this.pushUrl,
        cerType: options.cerType || 'RSA',
        specifyCFCA: options.specifyCFCA || 'FALSE',
        mobile: options.mobile,
        sid: options.sid
      }
    })
    return responseBody
  }

  /**
   * 查询CA机构及其电子认证服务协议
   * @param {String} account
   * @param {String} userType 用户类型：“1”代表个人，“2”代表企业
   * @param {Object} options
   * @returns {Object} {errno, errmsg, data}
  */
  async userGetPersonalCredential(account, userType, options = {}) {
    let routePath = '/realName/personal/identity3/vcode/sender/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        userType: userType,
        returnUrl: options.returnUrl || this.returnUrl,
        pushUrl: options.pushUrl || this.pushUrl,
        cerType: options.cerType || 'RSA',
        specifyCFCA: options.specifyCFCA || 'FALSE',
        mobile: options.mobile,
        sid: options.sid
      }
    })
    return responseBody
  }

  /**
   * 个人手机号三要素验证码获取
   * @param {String} account
   * @param {String} name 姓名/名称
   * @param {String} identity 证件号
   * @param {String} mobile 手机号
   * @param {Object} options
   * @param {String} options.identityType 证件类型，默认0：身份证
   * @param {String} options.userType 用户类型：“1”代表个人，“2”代表企业
   * @returns {Object} {errno, errmsg, data}
  */
  async realNamePersonalI3VcodeSender(account, name, identity, mobile, options = {}) {
    let routePath = '/realName/personal/identity3/vcode/sender/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        name: name,
        identity: identity,
        mobile: mobile,
        userType: options.userType || '1',
        identityType: options.identityType || '0',
      }
    })
    return responseBody
  }

  /**
   * 个人手机号三要素验证码校验
   * @param {String} vcode
   * @param {String} personalIdentity3Key
   * @returns {Object} {errno, errmsg, data}
  */
  async realNamePersonalI3VcodeVerify(vcode, personalIdentity3Key) {
    let routePath = '/realName/personal/identity3/vcode/verify/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        vcode: vcode,
        personalIdentity3Key: personalIdentity3Key
      }
    })
    return responseBody
  }

  /**
   * 银行卡多要素校验及发送验证码
   * @param {String} account
   * @param {String} name 姓名/名称
   * @param {String} identity 证件号
   * @param {String} mobile 银行卡预留手机号
   * @param {String} bankCard 银行卡号
   * @param {Object} options
   * @param {String} options.identityType 证件类型，默认0：身份证
   * @param {String} options.userType 用户类型：“1”代表个人，“2”代表企业
   * @returns {Object} {errno, errmsg, data}
  */
  async realNamePersonalI4VcodeSender(account, name, identity, mobile, bankCard, options = {}) {
    let routePath = '/realName/personal/identity4/vcode/sender/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        name: name,
        identity: identity,
        mobile: mobile,
        bankCard: bankCard,
        userType: options.userType || '1',
        identityType: options.identityType || '0'
      }
    })
    return responseBody
  }

  /**
   * 银行卡多要素验证码校验
   * @param {String} vcode
   * @param {String} personalIdentity4Key
   * @returns {Object} {errno, errmsg, data}
  */
  async realNamePersonalI4VcodeVerify(vcode, personalIdentity4Key) {
    let routePath = '/realName/personal/identity4/vcode/verify/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        vcode: vcode,
        personalIdentity4Key: personalIdentity4Key
      }
    })
    return responseBody
  }

  /**
   * 银行卡多要素校验及发送验证码（支持非身份证）
   * @param {String} account
   * @param {String} name 姓名/名称
   * @param {String} idCardNo 证件号
   * @param {String} idCardType 证件类型：1-军官证；2-护照；3-港澳居民来往内地通行证；4-台湾居民来往大陆通行证；
   * 5-警官证；6-士兵证；7-其他证件；08-旅行证；09-外国护照；10-外国人永久居留身份证；11-出入境通行证；12-港澳居民居住证；13-台湾居民居住证；
   * @param {String} mobile 银行卡预留手机号
   * @param {String} bankCard 银行卡号
   * @param {Object} options
   * @param {String} options.userType 用户类型：“1”代表个人，“2”代表企业
   * @returns {Object} {errno, errmsg, data}
  */
  async realNamePersonalI4PVcodeSender(account, name, idCardNo, idCardType, mobile, bankCard, options = {}) {
    let routePath = '/realName/personal/identity4Plus/vcode/sender/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        name: name,
        idCardNo: idCardNo,
        idCardType: idCardType,
        mobile: mobile,
        bankCard: bankCard,
        userType: options.userType || '1',
        identityType: options.identityType || '0'
      }
    })
    return responseBody
  }

  /**
   * 银行卡多要素验证码校验（支持非身份证）
   * @param {String} vcode
   * @param {String} personalIdentity4PlusKey
   * @returns {Object} {errno, errmsg, data}
  */
  async realNamePersonalI4VcodeVerify(vcode, personalIdentity4PlusKey) {
    let routePath = '/realName/personal/identity4Plus/vcode/verify/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        vcode: vcode,
        personalIdentity4PlusKey: personalIdentity4PlusKey
      }
    })
    return responseBody
  }

  /**
   * 刷脸认证
   * @param {String} account
   * @param {String} sid
   * @param {String} name
   * @param {String} identity
   * @param {String} returnUrl
   * @param {Object} options
   * @returns {Object} {errno, errmsg, data}
  */
  async realNamePersonalIdentityFace(account, sid, name, identity, returnUrl, options = {}) {
    let routePath = '/realName/personal/identity/face/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        sid: sid,
        name: name,
        identity: identity,
        returnUrl: returnUrl,
        returnMethod: options.returnMethod || 'get',
        callbackHost: options.callbackHost || '',
        pushUrl: options.pushUrl || this.pushUrl,
        userType: options.userType || '1',
      }
    })
    return responseBody
  }

  /**
   * 获取刷脸结果
   * @param {String} orderNo
   * @returns {Object} {errno, errmsg, data}
  */
  async realNamePersonalI2GetFaceAuthResult(orderNo) {
    let routePath = '/realName/personal/identity2/getFaceAuthResult/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        orderNo: orderNo
      }
    })
    return responseBody
  }

  /**
   * 企业银行打款（关联用户）
   * @param {String} account
   * @param {String} bankCard
   * @param {String} bankName
   * @param {String} bankAreaCode
   * @param {String} bankCardName
   * @param {Object} options {bankCode, remark, braBankName, unionNo}
   * @returns {Object} {errno, errmsg, data}
  */
  async realNameEnterpriseCorporateAccountAudit(account, bankCard, bankCard, bankName, bankAreaCode, bankCardName, options = {}) {
    let routePath = '/realName/enterprise/corporateAccountAudit/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        account: account,
        bankCard: bankCard,
        bankName: bankName,
        bankAreaCode: bankAreaCode,
        bankCardName: bankCardName,
        bankCode: options.bankCode || '',
        remark: options.remark || '',
        braBankName: options.braBankName || '',
        unionNo: options.unionNo || ''
      }
    })
    return responseBody
  }

  /**
   * 企业应答验证
   * @param {String} bankCard
   * @param {String} transactionAmount
   * @returns {Object} {errno, errmsg, data}
  */
  async credentialVerifyEnterprisePayAuthVerify(bankCard, transactionAmount) {  
    let routePath = '/credentialVerify/enterprise/payAuthVerify/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        bankCard: bankCard,
        transactionAmount: transactionAmount
      }
    })
    return responseBody
  }

  /**
   * 企业打款状态查询
   * @param {String} bizNo
   * @param {String} bankCard
   * @returns {Object} {errno, errmsg, data}
  */
  async credentialVerifyEnterprisePayAuthQuery(bizNo, bankCard) {
    let routePath = '/credentialVerify/enterprise/payAuthQuery/'
    let responseBody = await this.doRequest('POST', `${this.serverHost}${routePath}`, {
      form: {
        bizNo: bizNo,
        bankCard: bankCard
      }
    })
    return responseBody
  }
}

module.exports = SSQSign